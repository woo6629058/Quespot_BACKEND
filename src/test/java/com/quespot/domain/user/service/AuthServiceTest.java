package com.quespot.domain.user.service;

import com.quespot.domain.user.dto.req.LoginRequestDTO;
import com.quespot.domain.user.dto.req.SignUpRequestDTO;
import com.quespot.domain.user.entity.User;
import com.quespot.domain.user.enums.EmailVerificationPurpose;
import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.repository.UserProfileRepository;
import com.quespot.domain.user.repository.UserRepository;
import com.quespot.domain.user.repository.UserSocialAccountRepository;
import com.quespot.global.security.provider.JwtTokenPair;
import com.quespot.global.security.provider.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final Long USER_ID = 1L;
    private static final String EMAIL = "member@example.com";
    private static final String PASSWORD = "password1234";

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    @Mock
    private UserSocialAccountRepository userSocialAccountRepository;

    @Mock
    private OAuth2UnlinkQueueService oAuth2UnlinkQueueService;

    @Mock
    private EmailVerificationService emailVerificationService;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    @Test
    void signUpChecksDuplicateEmailWithinEmailProvider() {
        SignUpRequestDTO request = new SignUpRequestDTO(EMAIL, PASSWORD, PASSWORD);
        when(userRepository.existsByProviderAndEmail(LoginProvider.EMAIL, EMAIL)).thenReturn(false);
        when(emailVerificationService.isEmailVerified(EMAIL, EmailVerificationPurpose.SIGN_UP))
                .thenReturn(true);
        when(passwordEncoder.encode(PASSWORD)).thenReturn("encoded-password");
        when(userRepository.saveAndFlush(any(User.class)))
                .thenAnswer(invocation -> userWithId(invocation.getArgument(0)));

        var response = authService.signUp(request);

        assertThat(response.userId()).isEqualTo(USER_ID);
        assertThat(response.email()).isEqualTo(EMAIL);
        verify(userRepository).existsByProviderAndEmail(LoginProvider.EMAIL, EMAIL);
    }

    @Test
    void loginFindsEmailProviderAccount() {
        User user = userWithId(User.createEmailUser(EMAIL, "encoded-password"));
        JwtTokenPair tokenPair = new JwtTokenPair(
                "access-token",
                "refresh-token",
                "session-id",
                1209600L
        );
        when(userRepository.findByProviderAndEmailForUpdate(LoginProvider.EMAIL, EMAIL))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches(PASSWORD, "encoded-password")).thenReturn(true);
        when(jwtTokenProvider.issueTokenPair(USER_ID, user.getRole())).thenReturn(tokenPair);
        when(userProfileRepository.existsByUserId(USER_ID)).thenReturn(false);

        var result = authService.login(new LoginRequestDTO(EMAIL, PASSWORD));

        assertThat(result.response().userId()).isEqualTo(USER_ID);
        verify(userRepository).findByProviderAndEmailForUpdate(LoginProvider.EMAIL, EMAIL);
    }

    private User userWithId(User user) {
        ReflectionTestUtils.setField(user, "id", USER_ID);
        return user;
    }
}
