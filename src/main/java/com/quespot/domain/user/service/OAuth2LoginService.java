package com.quespot.domain.user.service;

import com.quespot.domain.user.converter.AuthConverter;
import com.quespot.domain.user.dto.token.LoginResultDTO;
import com.quespot.domain.user.entity.User;
import com.quespot.domain.user.entity.UserSocialAccount;
import com.quespot.domain.user.enums.LoginProvider;
import com.quespot.domain.user.enums.UserStatus;
import com.quespot.domain.user.exception.AuthException;
import com.quespot.domain.user.exception.code.AuthErrorCode;
import com.quespot.domain.user.repository.UserProfileRepository;
import com.quespot.domain.user.repository.UserRepository;
import com.quespot.domain.user.repository.UserSocialAccountRepository;
import com.quespot.global.security.provider.JwtTokenPair;
import com.quespot.global.security.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuth2LoginService {

    private final UserRepository userRepository;
    private final UserSocialAccountRepository userSocialAccountRepository;
    private final UserProfileRepository userProfileRepository;
    private final OAuth2LoginCodeService oAuth2LoginCodeService;
    private final OAuth2LinkRequestService oAuth2LinkRequestService;
    private final OAuth2TokenCipher oAuth2TokenCipher;
    private final OAuth2UnlinkTaskStateService oAuth2UnlinkTaskStateService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    // 소셜 로그인 사용자 확인 및 일회용 코드 발급 로직
    @Transactional
    public String prepareLogin(
            String registrationId,
            OAuth2User oAuth2User,
            OAuth2ProviderToken providerToken
    ) {
        LoginProvider provider = resolveProvider(registrationId);
        OAuth2UserInfo userInfo = resolveUserInfo(provider, oAuth2User);

        User user = userSocialAccountRepository
                .findByProviderAndProviderUserId(provider, userInfo.providerUserId())
                .map(account -> {
                    prepareForRelink(provider, userInfo.providerUserId());
                    account.updateProviderEmail(userInfo.email());
                    updateCredentials(account, providerToken);
                    return account.getUser();
                })
                .filter(foundUser -> foundUser.getStatus() == UserStatus.ACTIVE)
                .orElseGet(() -> createSocialUser(provider, userInfo, providerToken));

        return oAuth2LoginCodeService.issue(user.getId());
    }

    // 로그인된 사용자에게 OAuth 인증 결과의 소셜 계정을 연결하는 로직
    @Transactional
    public LoginProvider linkAccount(
            String linkNonce,
            String registrationId,
            OAuth2User oAuth2User,
            OAuth2ProviderToken providerToken
    ) {
        OAuth2LinkRequestService.LinkRequest linkRequest =
                oAuth2LinkRequestService.consume(linkNonce);
        LoginProvider provider = resolveProvider(registrationId);
        if (linkRequest.provider() != provider) {
            throw new AuthException(AuthErrorCode.INVALID_OAUTH2_LINK_REQUEST);
        }

        User user = userRepository.findByIdForUpdate(linkRequest.userId())
                .filter(foundUser -> foundUser.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_OAUTH2_LINK_REQUEST));
        OAuth2UserInfo userInfo = resolveUserInfo(provider, oAuth2User);

        UserSocialAccount providerAccount = userSocialAccountRepository
                .findByProviderAndProviderUserId(provider, userInfo.providerUserId())
                .orElse(null);
        if (providerAccount != null) {
            if (!providerAccount.getUser().getId().equals(user.getId())) {
                throw new AuthException(AuthErrorCode.SOCIAL_ACCOUNT_LINKED_TO_ANOTHER_USER);
            }
            providerAccount.updateProviderEmail(userInfo.email());
            updateCredentials(providerAccount, providerToken);
            prepareForRelink(provider, userInfo.providerUserId());
            return provider;
        }

        if (userSocialAccountRepository.findByUserIdAndProvider(user.getId(), provider).isPresent()) {
            throw new AuthException(AuthErrorCode.LOGIN_METHOD_ALREADY_LINKED);
        }

        try {
            userSocialAccountRepository.saveAndFlush(
                    UserSocialAccount.create(
                            user,
                            provider,
                            userInfo.providerUserId(),
                            userInfo.email(),
                            oAuth2TokenCipher.encrypt(providerToken.accessToken()),
                            oAuth2TokenCipher.encrypt(providerToken.refreshToken()),
                            providerToken.accessTokenExpiresAt()
                    )
            );
            prepareForRelink(provider, userInfo.providerUserId());
            return provider;
        } catch (DataIntegrityViolationException exception) {
            throw new AuthException(AuthErrorCode.SOCIAL_ACCOUNT_LINKED_TO_ANOTHER_USER);
        }
    }

    // 일회용 코드를 Quespot 토큰으로 교환하는 로직
    @Transactional
    public LoginResultDTO exchangeLoginCode(String code) {
        Long userId = oAuth2LoginCodeService.consume(code);
        User user = userRepository.findByIdForUpdate(userId)
                .filter(foundUser -> foundUser.getStatus() == UserStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_OAUTH2_LOGIN_CODE));

        JwtTokenPair tokenPair = jwtTokenProvider.issueTokenPair(user.getId(), user.getRole());
        refreshTokenService.saveRefreshToken(user.getId(), tokenPair);

        return AuthConverter.toLoginResultDTO(
                user,
                tokenPair,
                userProfileRepository.existsByUserId(user.getId())
        );
    }

    private User createSocialUser(
            LoginProvider provider,
            OAuth2UserInfo userInfo,
            OAuth2ProviderToken providerToken
    ) {
        try {
            User user = userRepository.saveAndFlush(
                    User.createSocialUser(userInfo.email(), provider)
            );
            userSocialAccountRepository.saveAndFlush(
                    UserSocialAccount.create(
                            user,
                            provider,
                            userInfo.providerUserId(),
                            userInfo.email(),
                            oAuth2TokenCipher.encrypt(providerToken.accessToken()),
                            oAuth2TokenCipher.encrypt(providerToken.refreshToken()),
                            providerToken.accessTokenExpiresAt()
                    )
            );
            prepareForRelink(provider, userInfo.providerUserId());
            return user;
        } catch (DataIntegrityViolationException exception) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }
    }

    private void updateCredentials(
            UserSocialAccount account,
            OAuth2ProviderToken providerToken
    ) {
        account.updateOAuth2Credentials(
                oAuth2TokenCipher.encrypt(providerToken.accessToken()),
                oAuth2TokenCipher.encrypt(providerToken.refreshToken()),
                providerToken.accessTokenExpiresAt()
        );
    }

    private void prepareForRelink(LoginProvider provider, String providerUserId) {
        oAuth2UnlinkTaskStateService.prepareForRelink(provider, providerUserId);
    }

    private LoginProvider resolveProvider(String registrationId) {
        if (registrationId == null || registrationId.isBlank()) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        try {
            LoginProvider provider = LoginProvider.valueOf(registrationId.toUpperCase(Locale.ROOT));
            if (provider == LoginProvider.EMAIL) {
                throw new IllegalArgumentException();
            }
            return provider;
        } catch (IllegalArgumentException exception) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }
    }

    private OAuth2UserInfo resolveUserInfo(LoginProvider provider, OAuth2User oAuth2User) {
        return switch (provider) {
            case GOOGLE -> resolveGoogleUserInfo(oAuth2User);
            case KAKAO -> resolveKakaoUserInfo(oAuth2User);
            case NAVER -> resolveNaverUserInfo(oAuth2User);
            default -> throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        };
    }

    private OAuth2UserInfo resolveGoogleUserInfo(OAuth2User oAuth2User) {
        if (!Boolean.TRUE.equals(oAuth2User.getAttribute("email_verified"))) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        return new OAuth2UserInfo(
                requireAttribute(oAuth2User, "sub"),
                normalizeEmail(requireAttribute(oAuth2User, "email"))
        );
    }

    private OAuth2UserInfo resolveKakaoUserInfo(OAuth2User oAuth2User) {
        Object providerUserId = oAuth2User.getAttribute("id");
        Object kakaoAccountAttribute = oAuth2User.getAttribute("kakao_account");

        if (!(providerUserId instanceof Number) || !(kakaoAccountAttribute instanceof Map<?, ?> kakaoAccount)) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        if (!Boolean.TRUE.equals(kakaoAccount.get("is_email_valid"))
                || !Boolean.TRUE.equals(kakaoAccount.get("is_email_verified"))) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        Object email = kakaoAccount.get("email");
        if (!(email instanceof String emailValue) || emailValue.isBlank()) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        return new OAuth2UserInfo(
                providerUserId.toString(),
                normalizeEmail(emailValue)
        );
    }

    private OAuth2UserInfo resolveNaverUserInfo(OAuth2User oAuth2User) {
        Object responseAttribute = oAuth2User.getAttribute("response");
        if (!(responseAttribute instanceof Map<?, ?> response)) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        Object providerUserId = response.get("id");
        Object email = response.get("email");
        if (!(providerUserId instanceof String providerUserIdValue)
                || providerUserIdValue.isBlank()
                || !(email instanceof String emailValue)
                || emailValue.isBlank()) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }

        return new OAuth2UserInfo(
                providerUserIdValue,
                normalizeEmail(emailValue)
        );
    }

    private String requireAttribute(OAuth2User oAuth2User, String attributeName) {
        Object attribute = oAuth2User.getAttribute(attributeName);
        if (!(attribute instanceof String value) || value.isBlank()) {
            throw new AuthException(AuthErrorCode.OAUTH2_LOGIN_FAILED);
        }
        return value;
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private record OAuth2UserInfo(String providerUserId, String email) {
    }
}
