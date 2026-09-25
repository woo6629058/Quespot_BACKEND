package com.quespot.domain.user.service;

import com.quespot.domain.user.converter.AuthConverter;
import com.quespot.domain.user.dto.req.SendEmailVerificationCodeRequestDTO;
import com.quespot.domain.user.dto.req.VerifyEmailCodeRequestDTO;
import com.quespot.domain.user.dto.res.SendEmailVerificationCodeResponseDTO;
import com.quespot.domain.user.dto.res.VerifyEmailCodeResponseDTO;
import com.quespot.domain.user.enums.EmailVerificationPurpose;
import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.exception.AuthException;
import com.quespot.domain.user.exception.code.AuthErrorCode;
import com.quespot.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private static final String KEY_PREFIX = "quespot:auth:email-verification";
    private static final Long VERIFICATION_FAILED = 0L;
    private static final Long VERIFICATION_SUCCEEDED = 1L;
    private static final Long VERIFICATION_ATTEMPT_LIMIT_EXCEEDED = 2L;
    private static final Long REQUEST_LIMIT_EXCEEDED = 1L;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final DefaultRedisScript<Long> VALIDATE_REQUEST_LIMIT_SCRIPT = new DefaultRedisScript<>("""
            local function incrementWithExpiration(key, expirationSeconds)
                local requestCount = redis.call('INCR', key)

                if requestCount == 1 then
                    redis.call('EXPIRE', key, expirationSeconds)
                end

                return requestCount
            end

            local expirationSeconds = tonumber(ARGV[1])
            local emailRequestCount = incrementWithExpiration(KEYS[1], expirationSeconds)
            local clientRequestCount = incrementWithExpiration(KEYS[2], expirationSeconds)

            if emailRequestCount > tonumber(ARGV[2]) or clientRequestCount > tonumber(ARGV[3]) then
                return 1
            end

            return 0
            """, Long.class);
    private static final DefaultRedisScript<Long> VERIFY_EMAIL_CODE_SCRIPT = new DefaultRedisScript<>("""
            local savedCode = redis.call('GET', KEYS[1])
            if not savedCode then
                return 0
            end

            local failedAttempts = tonumber(redis.call('GET', KEYS[2]) or '0')
            local failedAttemptLimit = tonumber(ARGV[2])

            if failedAttempts >= failedAttemptLimit then
                return 2
            end

            if savedCode == ARGV[1] then
                redis.call('DEL', KEYS[1])
                redis.call('DEL', KEYS[2])
                redis.call('SET', KEYS[3], 'true', 'EX', tonumber(ARGV[4]))
                return 1
            end

            failedAttempts = redis.call('INCR', KEYS[2])

            if failedAttempts == 1 then
                redis.call('EXPIRE', KEYS[2], tonumber(ARGV[3]))
            end

            if failedAttempts >= failedAttemptLimit then
                redis.call('DEL', KEYS[1])
                return 2
            end

            return 0
            """, Long.class);

    private final UserRepository userRepository;
    private final StringRedisTemplate stringRedisTemplate;
    private final JavaMailSender javaMailSender;

    @Value("${app.mail.verification-code-expiration-minutes}")
    private Integer verificationCodeExpirationMinutes;

    @Value("${app.mail.verification-code-request-window-minutes}")
    private Integer verificationCodeRequestWindowMinutes;

    @Value("${app.mail.verification-code-request-limit}")
    private Integer verificationCodeRequestLimit;

    @Value("${app.mail.verification-code-client-request-limit}")
    private Integer verificationCodeClientRequestLimit;

    @Value("${app.mail.verification-code-failed-attempt-limit}")
    private Integer verificationCodeFailedAttemptLimit;

    @Value("${app.mail.verification-completion-expiration-minutes}")
    private Integer verificationCompletionExpirationMinutes;

    @Value("${spring.mail.username:}")
    private String fromEmail;

    @Value("${app.mail.verification-code-secret}")
    private String verificationCodeSecret;

    // 이메일 인증 코드 발송 로직
    @Transactional
    public SendEmailVerificationCodeResponseDTO sendVerificationCode(
            SendEmailVerificationCodeRequestDTO request,
            String clientKey
    ) {
        String email = normalizeEmail(request.email());

        if (userRepository.existsByProviderAndEmail(LoginProvider.EMAIL, email)) {
            throw new AuthException(AuthErrorCode.DUPLICATE_EMAIL);
        }

        validateVerificationCodeRequestLimit(email, clientKey, EmailVerificationPurpose.SIGN_UP);

        String code = generateVerificationCode();
        String codeHash = hashVerificationCode(email, code);
        saveVerificationCode(email, clientKey, EmailVerificationPurpose.SIGN_UP, codeHash);

        sendMail(email, code);

        return AuthConverter.toSendEmailVerificationCodeResponseDTO(email, verificationCodeExpirationMinutes);
    }

    // 이메일 인증 코드 검증 로직
    @Transactional
    public VerifyEmailCodeResponseDTO verifyEmailCode(VerifyEmailCodeRequestDTO request, String clientKey) {
        String email = normalizeEmail(request.email());
        String codeHash = hashVerificationCode(email, request.code());
        EmailVerificationPurpose purpose = EmailVerificationPurpose.SIGN_UP;
        String codeKey = verificationCodeKey(email, clientKey, purpose);
        String failedAttemptKey = verificationFailedAttemptKey(email, clientKey, purpose);
        String verificationCompletedKey = verificationCompletedKey(email, purpose);
        Long verificationResult = stringRedisTemplate.execute(
                VERIFY_EMAIL_CODE_SCRIPT,
                List.of(codeKey, failedAttemptKey, verificationCompletedKey),
                codeHash,
                String.valueOf(verificationCodeFailedAttemptLimit),
                String.valueOf(Duration.ofMinutes(verificationCodeExpirationMinutes).toSeconds()),
                String.valueOf(Duration.ofMinutes(verificationCompletionExpirationMinutes).toSeconds())
        );

        if (VERIFICATION_SUCCEEDED.equals(verificationResult)) {
            return AuthConverter.toVerifyEmailCodeResponseDTO(email);
        }

        if (VERIFICATION_ATTEMPT_LIMIT_EXCEEDED.equals(verificationResult)) {
            throw new AuthException(AuthErrorCode.EMAIL_VERIFICATION_ATTEMPT_LIMIT_EXCEEDED);
        }

        if (VERIFICATION_FAILED.equals(verificationResult)) {
            throw new AuthException(AuthErrorCode.INVALID_EMAIL_VERIFICATION_CODE);
        }

        throw new AuthException(AuthErrorCode.INVALID_EMAIL_VERIFICATION_CODE);
    }

    // 이메일 인증 완료 여부 조회 로직
    public boolean isEmailVerified(String email, EmailVerificationPurpose purpose) {
        return Boolean.TRUE.equals(stringRedisTemplate.hasKey(verificationCompletedKey(email, purpose)));
    }

    private void validateVerificationCodeRequestLimit(
            String email,
            String clientKey,
            EmailVerificationPurpose purpose
    ) {
        String emailRequestLimitKey = verificationEmailRequestLimitKey(email, purpose);
        String clientRequestLimitKey = verificationClientRequestLimitKey(clientKey, purpose);
        Long requestLimitResult = stringRedisTemplate.execute(
                VALIDATE_REQUEST_LIMIT_SCRIPT,
                List.of(emailRequestLimitKey, clientRequestLimitKey),
                String.valueOf(Duration.ofMinutes(verificationCodeRequestWindowMinutes).toSeconds()),
                String.valueOf(verificationCodeRequestLimit),
                String.valueOf(verificationCodeClientRequestLimit)
        );

        if (REQUEST_LIMIT_EXCEEDED.equals(requestLimitResult)) {
            throw new AuthException(AuthErrorCode.EMAIL_VERIFICATION_REQUEST_LIMIT_EXCEEDED);
        }
    }

    private void saveVerificationCode(
            String email,
            String clientKey,
            EmailVerificationPurpose purpose,
            String codeHash
    ) {
        stringRedisTemplate.opsForValue().set(
                verificationCodeKey(email, clientKey, purpose),
                codeHash,
                Duration.ofMinutes(verificationCodeExpirationMinutes)
        );
        stringRedisTemplate.delete(verificationFailedAttemptKey(email, clientKey, purpose));
    }

    private void sendMail(String email, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        if (!fromEmail.isBlank()) {
            message.setFrom(fromEmail);
        }
        message.setTo(email);
        message.setSubject("[Quespot] 이메일 인증 코드");
        message.setText("""
                Quespot 이메일 인증 코드입니다.

                인증 코드: %s
                유효 시간: %d분
                """.formatted(code, verificationCodeExpirationMinutes));

        javaMailSender.send(message);
    }

    private String generateVerificationCode() {
        return String.valueOf(SECURE_RANDOM.nextInt(900000) + 100000);
    }

    private String hashVerificationCode(String email, String code) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(
                    "%s:%s:%s".formatted(email, code, verificationCodeSecret)
                            .getBytes(StandardCharsets.UTF_8)
            );
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 algorithm is not available.", exception);
        }
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String verificationCodeKey(String email, String clientKey, EmailVerificationPurpose purpose) {
        return "%s:code:%s:%s:%s".formatted(KEY_PREFIX, purpose, email, clientKey);
    }

    private String verificationEmailRequestLimitKey(String email, EmailVerificationPurpose purpose) {
        return "%s:request:email:%s:%s".formatted(KEY_PREFIX, purpose, email);
    }

    private String verificationClientRequestLimitKey(String clientKey, EmailVerificationPurpose purpose) {
        return "%s:request:client:%s:%s".formatted(KEY_PREFIX, purpose, clientKey);
    }

    private String verificationFailedAttemptKey(String email, String clientKey, EmailVerificationPurpose purpose) {
        return "%s:fail:%s:%s:%s".formatted(KEY_PREFIX, purpose, email, clientKey);
    }

    private String verificationCompletedKey(String email, EmailVerificationPurpose purpose) {
        return "%s:verified:%s:%s".formatted(KEY_PREFIX, purpose, email);
    }
}
