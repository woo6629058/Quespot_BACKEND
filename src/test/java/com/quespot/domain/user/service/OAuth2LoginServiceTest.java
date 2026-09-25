package com.quespot.domain.user.service;

import com.quespot.domain.user.entity.User;
import com.quespot.domain.user.entity.UserSocialAccount;
import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.exception.AuthException;
import com.quespot.domain.user.exception.code.AuthErrorCode;
import com.quespot.domain.user.repository.UserProfileRepository;
import com.quespot.domain.user.repository.UserRepository;
import com.quespot.domain.user.repository.UserSocialAccountRepository;
import com.quespot.global.security.provider.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2LoginServiceTest {

    private static final Long USER_ID = 1L;
    private static final String EMAIL = "member@example.com";
    private static final String PROVIDER_USER_ID = "google-user-id";
    private static final OAuth2ProviderToken PROVIDER_TOKEN =
            new OAuth2ProviderToken("access-token", "refresh-token", null);

    @Mock
    private UserRepository userRepository;

    @Mock
    private UserSocialAccountRepository userSocialAccountRepository;

    @Mock
    private UserProfileRepository userProfileRepository;

    @Mock
    private OAuth2LoginCodeService oAuth2LoginCodeService;

    @Mock
    private OAuth2LinkRequestService oAuth2LinkRequestService;

    @Mock
    private OAuth2TokenCipher oAuth2TokenCipher;

    @Mock
    private OAuth2UnlinkTaskStateService oAuth2UnlinkTaskStateService;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    @InjectMocks
    private OAuth2LoginService oAuth2LoginService;

    @Test
    void createsSocialUserWithoutCheckingEmailUsedByAnotherProvider() {
        OAuth2User oAuth2User = googleUser();
        when(userSocialAccountRepository.findByProviderAndProviderUserId(
                LoginProvider.GOOGLE,
                PROVIDER_USER_ID
        )).thenReturn(Optional.empty());
        when(oAuth2TokenCipher.encrypt("access-token")).thenReturn("encrypted-access-token");
        when(oAuth2TokenCipher.encrypt("refresh-token")).thenReturn("encrypted-refresh-token");
        when(userRepository.saveAndFlush(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            ReflectionTestUtils.setField(user, "id", USER_ID);
            return user;
        });
        when(userSocialAccountRepository.saveAndFlush(any(UserSocialAccount.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(oAuth2LoginCodeService.issue(USER_ID)).thenReturn("login-code");

        String loginCode = oAuth2LoginService.prepareLogin("google", oAuth2User, PROVIDER_TOKEN);

        assertThat(loginCode).isEqualTo("login-code");
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(userCaptor.capture());
        assertThat(userCaptor.getValue().getProvider()).isEqualTo(LoginProvider.GOOGLE);
        assertThat(userCaptor.getValue().getEmail()).isEqualTo(EMAIL);
        verify(userRepository, never()).existsByProviderAndEmail(any(), anyString());
    }

    @Test
    void rejectsLinkWhenSocialAccountBelongsToAnotherUser() {
        User currentUser = userWithId(User.createEmailUser(EMAIL, "encoded-password"), USER_ID);
        User otherUser = userWithId(
                User.createSocialUser("other@example.com", LoginProvider.GOOGLE),
                2L
        );
        UserSocialAccount existingAccount = UserSocialAccount.create(
                otherUser,
                LoginProvider.GOOGLE,
                PROVIDER_USER_ID,
                EMAIL,
                "encrypted-access-token",
                "encrypted-refresh-token",
                null
        );
        when(oAuth2LinkRequestService.consume("link-nonce"))
                .thenReturn(new OAuth2LinkRequestService.LinkRequest(USER_ID, LoginProvider.GOOGLE));
        when(userRepository.findByIdForUpdate(USER_ID)).thenReturn(Optional.of(currentUser));
        when(userSocialAccountRepository.findByProviderAndProviderUserId(
                LoginProvider.GOOGLE,
                PROVIDER_USER_ID
        )).thenReturn(Optional.of(existingAccount));

        assertThatThrownBy(() -> oAuth2LoginService.linkAccount(
                "link-nonce",
                "google",
                googleUser(),
                PROVIDER_TOKEN
        )).isInstanceOfSatisfying(AuthException.class, exception ->
                assertThat(exception.getErrorCode())
                        .isEqualTo(AuthErrorCode.SOCIAL_ACCOUNT_LINKED_TO_ANOTHER_USER)
        );
    }

    private OAuth2User googleUser() {
        OAuth2User oAuth2User = org.mockito.Mockito.mock(OAuth2User.class);
        when(oAuth2User.<Boolean>getAttribute("email_verified")).thenReturn(true);
        when(oAuth2User.<String>getAttribute("sub")).thenReturn(PROVIDER_USER_ID);
        when(oAuth2User.<String>getAttribute("email")).thenReturn(EMAIL);
        return oAuth2User;
    }

    private User userWithId(User user, Long id) {
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }
}
