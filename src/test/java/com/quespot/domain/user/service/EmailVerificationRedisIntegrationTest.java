package com.quespot.domain.user.service;

import com.quespot.domain.user.dto.req.SendEmailVerificationCodeRequestDTO;
import com.quespot.domain.user.dto.req.VerifyEmailCodeRequestDTO;
import com.quespot.domain.user.enums.EmailVerificationPurpose;
import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.exception.AuthException;
import com.quespot.domain.user.exception.code.AuthErrorCode;
import com.quespot.domain.user.repository.UserRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Testcontainers
class EmailVerificationRedisIntegrationTest {

    private static final String KEY_PREFIX = "quespot:auth:email-verification";
    private static final String PURPOSE = EmailVerificationPurpose.SIGN_UP.name();
    private static final int REDIS_PORT = 6379;
    private static final Pattern VERIFICATION_CODE_PATTERN = Pattern.compile("인증 코드: (\\d{6})");

    @Container
    private static final GenericContainer<?> REDIS = new GenericContainer<>(
            DockerImageName.parse("redis:8.0-alpine")
    ).withExposedPorts(REDIS_PORT);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate stringRedisTemplate;

    private UserRepository userRepository;
    private JavaMailSender javaMailSender;
    private EmailVerificationService emailVerificationService;

    @BeforeAll
    static void setUpRedis() {
        connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(REDIS_PORT));
        connectionFactory.afterPropertiesSet();

        stringRedisTemplate = new StringRedisTemplate(connectionFactory);
        stringRedisTemplate.afterPropertiesSet();
    }

    @AfterAll
    static void tearDownRedis() {
        connectionFactory.destroy();
    }

    @BeforeEach
    void setUp() {
        stringRedisTemplate.execute((RedisCallback<Void>) connection -> {
            connection.serverCommands().flushDb();
            return null;
        });

        userRepository = mock(UserRepository.class);
        javaMailSender = mock(JavaMailSender.class);
        emailVerificationService = new EmailVerificationService(
                userRepository,
                stringRedisTemplate,
                javaMailSender
        );

        ReflectionTestUtils.setField(emailVerificationService, "verificationCodeExpirationMinutes", 10);
        ReflectionTestUtils.setField(emailVerificationService, "verificationCodeRequestWindowMinutes", 10);
        ReflectionTestUtils.setField(emailVerificationService, "verificationCodeRequestLimit", 5);
        ReflectionTestUtils.setField(emailVerificationService, "verificationCodeClientRequestLimit", 20);
        ReflectionTestUtils.setField(emailVerificationService, "verificationCodeFailedAttemptLimit", 5);
        ReflectionTestUtils.setField(emailVerificationService, "verificationCompletionExpirationMinutes", 30);
        ReflectionTestUtils.setField(emailVerificationService, "fromEmail", "noreply@quespot.test");
        ReflectionTestUtils.setField(
                emailVerificationService,
                "verificationCodeSecret",
                "redis-integration-test-verification-code-secret"
        );

        when(userRepository.existsByProviderAndEmail(eq(LoginProvider.EMAIL), anyString())).thenReturn(false);
    }

    @Test
    void limitsVerificationCodeRequestsByEmail() {
        String email = "member@quespot.test";
        String clientKey = "client-a";

        for (int requestCount = 0; requestCount < 5; requestCount++) {
            sendVerificationCode(email, clientKey);
        }

        AuthException exception = assertThrows(
                AuthException.class,
                () -> sendVerificationCode(email, "client-b")
        );

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.EMAIL_VERIFICATION_REQUEST_LIMIT_EXCEEDED);
        assertThat(stringRedisTemplate.opsForValue().get(emailRequestLimitKey(email))).isEqualTo("6");
        assertTtlWithin(emailRequestLimitKey(email), Duration.ofMinutes(10));
    }

    @Test
    void limitsVerificationCodeRequestsByClientAcrossDifferentEmails() {
        String clientKey = "shared-client";

        for (int requestCount = 0; requestCount < 20; requestCount++) {
            sendVerificationCode("member%d@quespot.test".formatted(requestCount), clientKey);
        }

        AuthException exception = assertThrows(
                AuthException.class,
                () -> sendVerificationCode("blocked@quespot.test", clientKey)
        );

        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.EMAIL_VERIFICATION_REQUEST_LIMIT_EXCEEDED);
        assertThat(stringRedisTemplate.opsForValue().get(clientRequestLimitKey(clientKey))).isEqualTo("21");
        assertTtlWithin(clientRequestLimitKey(clientKey), Duration.ofMinutes(10));
    }

    @Test
    void storesHashedVerificationCodeWithExpiration() {
        String email = "member@quespot.test";
        String clientKey = "client-a";

        sendVerificationCode(email, clientKey);

        String verificationCode = latestSentVerificationCode();
        String storedCode = stringRedisTemplate.opsForValue().get(codeKey(email, clientKey));

        assertThat(storedCode)
                .isNotNull()
                .hasSize(64)
                .isNotEqualTo(verificationCode);
        assertTtlWithin(codeKey(email, clientKey), Duration.ofMinutes(10));
    }

    @Test
    void invalidatesCodeAfterFifthFailedVerification() {
        String email = "member@quespot.test";
        String clientKey = "client-a";

        sendVerificationCode(email, clientKey);
        String verificationCode = latestSentVerificationCode();
        String invalidCode = verificationCode.equals("000000") ? "000001" : "000000";

        for (int failedAttempt = 0; failedAttempt < 4; failedAttempt++) {
            AuthException exception = assertThrows(
                    AuthException.class,
                    () -> verifyEmailCode(email, invalidCode, clientKey)
            );
            assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.INVALID_EMAIL_VERIFICATION_CODE);
        }

        AuthException exception = assertThrows(
                AuthException.class,
                () -> verifyEmailCode(email, invalidCode, clientKey)
        );

        assertThat(exception.getErrorCode())
                .isEqualTo(AuthErrorCode.EMAIL_VERIFICATION_ATTEMPT_LIMIT_EXCEEDED);
        assertThat(stringRedisTemplate.hasKey(codeKey(email, clientKey))).isFalse();
        assertThat(stringRedisTemplate.opsForValue().get(failedAttemptKey(email, clientKey))).isEqualTo("5");
    }

    @Test
    void completesVerificationOnlyOnceAndSetsCompletionExpiration() {
        String email = "member@quespot.test";
        String clientKey = "client-a";

        sendVerificationCode(email, clientKey);
        String verificationCode = latestSentVerificationCode();
        String invalidCode = verificationCode.equals("000000") ? "000001" : "000000";
        assertThrows(AuthException.class, () -> verifyEmailCode(email, invalidCode, clientKey));

        emailVerificationService.verifyEmailCode(
                new VerifyEmailCodeRequestDTO(email, verificationCode),
                clientKey
        );

        assertThat(stringRedisTemplate.hasKey(codeKey(email, clientKey))).isFalse();
        assertThat(stringRedisTemplate.hasKey(failedAttemptKey(email, clientKey))).isFalse();
        assertThat(stringRedisTemplate.opsForValue().get(verifiedKey(email))).isEqualTo("true");
        assertTtlWithin(verifiedKey(email), Duration.ofMinutes(30));

        AuthException exception = assertThrows(
                AuthException.class,
                () -> verifyEmailCode(email, verificationCode, clientKey)
        );
        assertThat(exception.getErrorCode()).isEqualTo(AuthErrorCode.INVALID_EMAIL_VERIFICATION_CODE);
    }

    @Test
    void preservesCompletedVerificationWhenRequestingNewCode() {
        String email = "member@quespot.test";

        sendVerificationCode(email, "client-a");
        String verificationCode = latestSentVerificationCode();
        verifyEmailCode(email, verificationCode, "client-a");
        Long completionTtlBeforeRequest = stringRedisTemplate.getExpire(verifiedKey(email), TimeUnit.SECONDS);

        reset(javaMailSender);
        sendVerificationCode(email, "client-b");
        Long completionTtlAfterRequest = stringRedisTemplate.getExpire(verifiedKey(email), TimeUnit.SECONDS);

        assertThat(stringRedisTemplate.opsForValue().get(verifiedKey(email))).isEqualTo("true");
        assertThat(completionTtlAfterRequest)
                .isPositive()
                .isLessThanOrEqualTo(completionTtlBeforeRequest);
    }

    @Test
    void doesNotBypassEmailLimitWithConcurrentRequests() throws Exception {
        int concurrentRequestCount = 20;
        ExecutorService executorService = Executors.newFixedThreadPool(concurrentRequestCount);
        CountDownLatch ready = new CountDownLatch(concurrentRequestCount);
        CountDownLatch start = new CountDownLatch(1);

        try {
            List<Future<Boolean>> results = java.util.stream.IntStream.range(0, concurrentRequestCount)
                    .mapToObj(index -> executorService.submit(() -> {
                        ready.countDown();
                        start.await();

                        try {
                            sendVerificationCode("concurrent@quespot.test", "client-%d".formatted(index));
                            return true;
                        } catch (AuthException exception) {
                            if (exception.getErrorCode() == AuthErrorCode.EMAIL_VERIFICATION_REQUEST_LIMIT_EXCEEDED) {
                                return false;
                            }
                            throw exception;
                        }
                    }))
                    .toList();

            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            long successCount = 0;
            for (Future<Boolean> result : results) {
                if (result.get(10, TimeUnit.SECONDS)) {
                    successCount++;
                }
            }

            assertThat(successCount).isEqualTo(5);
            assertThat(stringRedisTemplate.opsForValue().get(emailRequestLimitKey("concurrent@quespot.test")))
                    .isEqualTo(String.valueOf(concurrentRequestCount));
        } finally {
            executorService.shutdownNow();
        }
    }

    private void sendVerificationCode(String email, String clientKey) {
        emailVerificationService.sendVerificationCode(
                new SendEmailVerificationCodeRequestDTO(email),
                clientKey
        );
    }

    private void verifyEmailCode(String email, String code, String clientKey) {
        emailVerificationService.verifyEmailCode(
                new VerifyEmailCodeRequestDTO(email, code),
                clientKey
        );
    }

    private String latestSentVerificationCode() {
        org.mockito.ArgumentCaptor<SimpleMailMessage> messageCaptor =
                org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(javaMailSender, atLeastOnce()).send(messageCaptor.capture());

        List<SimpleMailMessage> messages = messageCaptor.getAllValues();
        String messageText = Objects.requireNonNull(messages.get(messages.size() - 1).getText());
        Matcher matcher = VERIFICATION_CODE_PATTERN.matcher(messageText);

        assertThat(matcher.find()).isTrue();
        return matcher.group(1);
    }

    private void assertTtlWithin(String key, Duration expectedMaximum) {
        Long ttl = stringRedisTemplate.getExpire(key, TimeUnit.SECONDS);

        assertThat(ttl)
                .isPositive()
                .isLessThanOrEqualTo(expectedMaximum.toSeconds());
    }

    private String codeKey(String email, String clientKey) {
        return "%s:code:%s:%s:%s".formatted(KEY_PREFIX, PURPOSE, email, clientKey);
    }

    private String emailRequestLimitKey(String email) {
        return "%s:request:email:%s:%s".formatted(KEY_PREFIX, PURPOSE, email);
    }

    private String clientRequestLimitKey(String clientKey) {
        return "%s:request:client:%s:%s".formatted(KEY_PREFIX, PURPOSE, clientKey);
    }

    private String failedAttemptKey(String email, String clientKey) {
        return "%s:fail:%s:%s:%s".formatted(KEY_PREFIX, PURPOSE, email, clientKey);
    }

    private String verifiedKey(String email) {
        return "%s:verified:%s:%s".formatted(KEY_PREFIX, PURPOSE, email);
    }
}
