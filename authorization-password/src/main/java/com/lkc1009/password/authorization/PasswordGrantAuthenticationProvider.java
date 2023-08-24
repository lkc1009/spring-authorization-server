package com.lkc1009.password.authorization;

import com.lkc1009.password.user.UserService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator;
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public PasswordGrantAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService,
                                               OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator) {
        Assert.notNull(oAuth2AuthorizationService, "authorizationService cannot be null");
        Assert.notNull(oAuth2TokenGenerator, "tokenGenerator cannot be null");
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
        this.oAuth2TokenGenerator = oAuth2TokenGenerator;
    }

    private static OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken(@NotNull Authentication authentication) {
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (Objects.nonNull(oAuth2ClientAuthenticationToken) && oAuth2ClientAuthenticationToken.isAuthenticated()) {
            return oAuth2ClientAuthenticationToken;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    private Set<String> getIntersSet(Set<String> set1, Set<String> set2) {
        if (CollectionUtils.isEmpty(set1) || CollectionUtils.isEmpty(set2)) {
            return Set.of();
        }
        Set<String> set = set1.stream().filter(set2::contains).collect(Collectors.toSet());
        if (CollectionUtils.isEmpty(set)) {
            set = Set.of();
        }
        return set;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        PasswordGrantAuthenticationToken passwordGrantAuthenticationToken = (PasswordGrantAuthenticationToken) authentication;

        Map<String, Object> additionalParameters = passwordGrantAuthenticationToken.getAdditionalParameters();

        // 授权类型
        AuthorizationGrantType authorizationGrantType = passwordGrantAuthenticationToken.getGrantType();
        // 用户名
        String username = additionalParameters.get(OAuth2ParameterNames.USERNAME).toString();
        // 密码
        String password = additionalParameters.get(OAuth2ParameterNames.PASSWORD).toString();

        // 请求参数权限范围
        String requestScopesStr = (String) additionalParameters.get(OAuth2ParameterNames.SCOPE);
        // 请求参数权限范围专场集合
        Set<String> requestScopeSet = Stream.of(requestScopesStr.split(" ")).collect(Collectors.toSet());

        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = oAuth2ClientAuthenticationToken(passwordGrantAuthenticationToken);
        RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();

        // Ensure the client is configured to use this authorization grant type
        assert registeredClient != null;
        if (!registeredClient.getAuthorizationGrantTypes().contains(authorizationGrantType)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 检验用户名信息
        UserDetails userDetails = userService.loadUserByUsername(username);
        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new OAuth2AuthenticationException("密码错误");
        }

        // 由于在上面已验证过用户名、密码，现在构建一个已认证的对象 UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken.authenticated(userDetails, oAuth2ClientAuthenticationToken, userDetails.getAuthorities());

        // Initialize the DefaultOAuth2TokenContext
        DefaultOAuth2TokenContext.Builder defaultOAuth2TokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(requestScopeSet)
                .authorizationGrantType(authorizationGrantType)
                .authorizationGrant(passwordGrantAuthenticationToken);

        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder oauth2AuthorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(oAuth2ClientAuthenticationToken.getName())
                .authorizedScopes(requestScopeSet)
                .attribute(Principal.class.getName(), usernamePasswordAuthenticationToken)
                .authorizationGrantType(authorizationGrantType);

        // ----- Access token -----
        OAuth2TokenContext oAuth2TokenContext = defaultOAuth2TokenContext.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token oAuth2Token = this.oAuth2TokenGenerator.generate(oAuth2TokenContext);

        if (Objects.isNull(oAuth2Token)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        // Generate the access token
        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                oAuth2Token.getTokenValue(), oAuth2Token.getIssuedAt(), oAuth2Token.getExpiresAt(), oAuth2TokenContext.getAuthorizedScopes());

        if (oAuth2Token instanceof ClaimAccessor) {
            oauth2AuthorizationBuilder.token(oAuth2AccessToken, stringObjectMap ->
                    stringObjectMap.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) oAuth2Token).getClaims())
            );
        } else {
            oauth2AuthorizationBuilder.accessToken(oAuth2AccessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken oAuth2RefreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                // Do not issue refresh token to public client
                !oAuth2ClientAuthenticationToken.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            oAuth2TokenContext = defaultOAuth2TokenContext.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.oAuth2TokenGenerator.generate(oAuth2TokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            oAuth2RefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            oauth2AuthorizationBuilder.refreshToken(oAuth2RefreshToken);
        }

        // 获取客户端权限范围和请求参数权限范围的交集
        Set<String> scopeSet = getIntersSet(registeredClient.getScopes(), requestScopeSet);
        // ID Token
        OidcIdToken oidcIdToken;
        if (scopeSet.contains(OidcScopes.OPENID)) {
            oAuth2TokenContext = defaultOAuth2TokenContext
                    .tokenType(ID_TOKEN_TOKEN_TYPE)
                    .authorization(oauth2AuthorizationBuilder.build())
                    .build();

            OAuth2Token idToken = this.oAuth2TokenGenerator.generate(oAuth2TokenContext);

            if (!(idToken instanceof Jwt)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the ID token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            oidcIdToken = new OidcIdToken(idToken.getTokenValue(), idToken.getIssuedAt(),
                    idToken.getExpiresAt(), ((Jwt) idToken).getClaims());
            oauth2AuthorizationBuilder.token(oidcIdToken, (metadata) -> {
                        metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, oidcIdToken.getClaims());
                    }
            );
        } else {
            oidcIdToken = null;
        }

        OAuth2Authorization oAuth2Authorization = oauth2AuthorizationBuilder.build();

        // Save the Oauth2Authorization
        this.oAuth2AuthorizationService.save(oAuth2Authorization);

        if (Objects.nonNull(oidcIdToken)) {
            additionalParameters = new HashMap<>();
            additionalParameters.put(OidcParameterNames.ID_TOKEN, oidcIdToken.getTokenValue());
        }

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, oAuth2ClientAuthenticationToken, oAuth2AccessToken, oAuth2RefreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
