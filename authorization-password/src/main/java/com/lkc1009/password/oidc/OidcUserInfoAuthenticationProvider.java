package com.lkc1009.password.oidc;

import com.lkc1009.password.user.oidc.OidcUserInfo;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.*;
import java.util.function.Function;

@Slf4j
public class OidcUserInfoAuthenticationProvider implements AuthenticationProvider {
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private Function<OidcUserInfoAuthenticationContext, OidcUserInfo> oidcUserInfoAuthenticationContextOidcUserInfoFunction = new OidcUserInfoAuthenticationProvider.DefaultOidcUserInfoMapper();

    public OidcUserInfoAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.oAuth2AuthorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OidcUserInfoAuthenticationToken userInfoAuthentication = (OidcUserInfoAuthenticationToken) authentication;
        AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;

        if (AbstractOAuth2TokenAuthenticationToken.class.isAssignableFrom(userInfoAuthentication.getPrincipal().getClass())) {
            accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<OAuth2Token>) userInfoAuthentication.getPrincipal();
        }

        if (accessTokenAuthentication != null && accessTokenAuthentication.isAuthenticated()) {
            String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();
            OAuth2Authorization authorization = this.oAuth2AuthorizationService.findByToken(accessTokenValue, OAuth2TokenType.ACCESS_TOKEN);

            if (authorization == null) {
                throw new OAuth2AuthenticationException("invalid_token");

            } else {
                OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
                
                if (!authorizedAccessToken.isActive()) {
                    throw new OAuth2AuthenticationException("invalid_token");
                } else {
                    // 从认证结果中获取 userInfo
                    OidcUserInfo oidcUserInfo = (OidcUserInfo) userInfoAuthentication.getUserInfo();
                    // 从 authorizedAccessToken 中获取授权范围
                    Set<String> scopeSet = (HashSet<String>) authorizedAccessToken.getClaims().get("scope");
                    // 获取授权范围对应 userInfo 的字段信息
                    Map<String, Object> claims = DefaultOidcUserInfoMapper.getClaimsRequestedByScope(oidcUserInfo.getClaims(), scopeSet);
                    // 构造新的 OidcUserInfoAuthenticationToken
                    return new OidcUserInfoAuthenticationToken(accessTokenAuthentication, new OidcUserInfo(claims));
                }
            }
        } else {
            throw new OAuth2AuthenticationException("invalid_token");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OidcUserInfoAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setOidcUserInfoAuthenticationContextOidcUserInfoFunction(Function<OidcUserInfoAuthenticationContext, OidcUserInfo> oidcUserInfoAuthenticationContextOidcUserInfoFunction) {
        Assert.notNull(oidcUserInfoAuthenticationContextOidcUserInfoFunction, "oidcUserInfoAuthenticationContextOidcUserInfoFunction cannot be null");
        this.oidcUserInfoAuthenticationContextOidcUserInfoFunction = oidcUserInfoAuthenticationContextOidcUserInfoFunction;
    }

    private static final class DefaultOidcUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {
        private static final List<String> EMAIL_CLAIMS = Arrays.asList("email", "email_verified");
        private static final List<String> PROFILE_CLAIMS = Arrays.asList("name", "username", "description", "status", "profile");


        private DefaultOidcUserInfoMapper() {
        }

        private static @NotNull Map<String, Object> getClaimsRequestedByScope(Map<String, Object> claims, @NotNull Set<String> requestedScopes) {
            Set<String> scopeRequestedClaimNames = new HashSet<>(32);
            scopeRequestedClaimNames.add("sub");

            if (requestedScopes.contains("email")) {
                scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
            }

            if (requestedScopes.contains("profile")) {
                scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
            }

            Map<String, Object> requestedClaims = new HashMap<>(claims);
            requestedClaims.keySet().removeIf((claimName) -> !scopeRequestedClaimNames.contains(claimName));
            return requestedClaims;
        }

        public @NotNull OidcUserInfo apply(@NotNull OidcUserInfoAuthenticationContext authenticationContext) {
            OAuth2Authorization authorization = authenticationContext.getAuthorization();
            OidcIdToken idToken = Objects.requireNonNull(authorization.getToken(OidcIdToken.class)).getToken();
            OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
            Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(idToken.getClaims(), accessToken.getScopes());
            return new OidcUserInfo(scopeRequestedClaims);
        }
    }
}