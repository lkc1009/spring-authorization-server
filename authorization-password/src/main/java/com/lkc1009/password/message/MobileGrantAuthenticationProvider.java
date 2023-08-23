package com.lkc1009.password.message;

import com.lkc1009.password.constant.OAuth2Constant;
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

import java.security.Principal;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MobileGrantAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator;

    public MobileGrantAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService,
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

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobileGrantAuthenticationToken mobileGrantAuthenticationToken =
                (MobileGrantAuthenticationToken) authentication;

        Map<String, Object> additionalParameters = mobileGrantAuthenticationToken.getAdditionalParameters();
        // 授权类型
        AuthorizationGrantType authorizationGrantType = mobileGrantAuthenticationToken.getGrantType();
        // 用户名
        String username = (String)additionalParameters.get(OAuth2ParameterNames.USERNAME);
        // 短信验证码
        String smsCode = (String)additionalParameters.get(OAuth2Constant.SMS_CODE);
        // 请求参数权限范围
        String requestScopesStr = (String)additionalParameters.get(OAuth2ParameterNames.SCOPE);
        // 请求参数权限范围专场集合
        Set<String> requestScopeSet = Stream.of(requestScopesStr.split(" ")).collect(Collectors.toSet());

        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken =
                oAuth2ClientAuthenticationToken(mobileGrantAuthenticationToken);
        RegisteredClient registeredClient = oAuth2ClientAuthenticationToken.getRegisteredClient();

        // Ensure the client is configured to use this authorization grant type
        assert registeredClient != null;
        if (!registeredClient.getAuthorizationGrantTypes().contains(authorizationGrantType)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        // 校验用户名信息
        UserDetails userDetails = userService.loadUserByUsername(username);
        // 校验短信验证码
        if(!OAuth2Constant.SMS_CODE_VALUE.equals(smsCode)){
            throw new OAuth2AuthenticationException("短信验证码不正确！");
        }

        // 由于在上面已验证过用户名、密码，现在构建一个已认证的对象 UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = UsernamePasswordAuthenticationToken.authenticated(userDetails,oAuth2ClientAuthenticationToken,userDetails.getAuthorities());

        // Initialize the DefaultOAuth2TokenContext
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(usernamePasswordAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(authorizationGrantType)
                .authorizedScopes(requestScopeSet)
                .authorizationGrant(mobileGrantAuthenticationToken);

        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(oAuth2ClientAuthenticationToken.getName())
                .authorizedScopes(requestScopeSet)
                .attribute(Principal.class.getName(), usernamePasswordAuthenticationToken)
                .authorizationGrantType(authorizationGrantType);

        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.oAuth2TokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                // Do not issue refresh token to public client
                !oAuth2ClientAuthenticationToken.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.oAuth2TokenGenerator.generate(tokenContext);

            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(oAuth2Error);
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        // 保存认证信息
        OAuth2Authorization authorization = authorizationBuilder.build();
        this.oAuth2AuthorizationService.save(authorization);

        return  new OAuth2AccessTokenAuthenticationToken(
                registeredClient, oAuth2ClientAuthenticationToken, accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MobileGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
