package com.lkc1009.password.authorization;

import com.lkc1009.password.user.UserService;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
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

import java.util.Map;
import java.util.Objects;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserService userService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator;

    public PasswordGrantAuthenticationProvider(OAuth2AuthorizationService oAuth2AuthorizationService,
                                               OAuth2TokenGenerator<? extends OAuth2Token> oAuth2TokenGenerator) {
        Assert.notNull(oAuth2AuthorizationService, "authorizationService cannot be null");
        Assert.notNull(oAuth2TokenGenerator, "tokenGenerator cannot be null");
        this.oAuth2AuthorizationService = oAuth2AuthorizationService;
        this.oAuth2TokenGenerator = oAuth2TokenGenerator;
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

        // Generate the access token
        OAuth2TokenContext oAuth2TokenContext = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(oAuth2ClientAuthenticationToken)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(authorizationGrantType)
                .authorizationGrant(passwordGrantAuthenticationToken)
                .build();

        OAuth2Token oAuth2Token = this.oAuth2TokenGenerator.generate(oAuth2TokenContext);
        if (Objects.isNull(oAuth2Token)) {
            OAuth2Error oAuth2Error = new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generation failed to generate a access token.", null);
            throw new OAuth2AuthenticationException(oAuth2Error);
        }

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                oAuth2Token.getTokenValue(), oAuth2Token.getIssuedAt(), oAuth2Token.getExpiresAt(), null);

        // Initialize the OAuth2Authentication
        OAuth2Authorization.Builder oAuth2AuthorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(oAuth2ClientAuthenticationToken.getName())
                .authorizationGrantType(authorizationGrantType);

        if (oAuth2Token instanceof ClaimAccessor) {
            oAuth2AuthorizationBuilder.token(oAuth2AccessToken, stringObjectMap ->
                    stringObjectMap.put(
                            OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                            ((ClaimAccessor) oAuth2Token).getClaims())
                    );
        } else {
            oAuth2AuthorizationBuilder.accessToken(oAuth2AccessToken);
        }

        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationBuilder.build();

        // Save the Oauth2Authorization
        this.oAuth2AuthorizationService.save(oAuth2Authorization);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient, oAuth2ClientAuthenticationToken, oAuth2AccessToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
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
}
