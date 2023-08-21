package com.lkc1009.server.security;

//import com.lkc1009.authorization.filter.JwtAuthenticationTokenFilter;
//import com.lkc1009.authorization.handler.AccessDeniedSecurityHandler;
//import com.lkc1009.authorization.handler.AuthenticationSecurityEntryPoint;
//import com.lkc1009.authorization.user.UserService;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.lkc1009.server.user.User;
import com.lkc1009.server.user.UserMixin;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

/**
 * security 配置类
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
//    private final UserService userService;
//    private final AccessDeniedSecurityHandler accessDeniedSecurityHandler;
//    private final AuthenticationSecurityEntryPoint authenticationSecurityEntryPoint;
//    private final JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter;
    /**
     * 密码加密方式
     * @return passwordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 用户信息
     * @return userDetailsService
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        var user = User.withUsername("user")
//                // 密文
//                .password("$2a$10$WMkKx7wwlAwegIOU3MHFfuo9lemdGp380FB12rJ3Sis89V8IA3GiK")
//                .roles("USER")
//                .build();
//        // 内存中添加一个用户
//        return new InMemoryUserDetailsManager(user);
//    }

    /**
     * Spring Authorization Server 相关配置
     * 此处方法与下面 defaultSecurityFilterChain 都是 SecurityFilterChain 配置，配置的内容有点区别，
     * 因为 Spring Authorization Server 是建立在 Spring Security 基础上的，defaultSecurityFilterChain 方法主要
     * 配置 Spring Security 相关的东西，而此处 authorizationServerSecurityFilterChain 方法主要配置 OAuth 2.1 和 OpenID Connect 1.0 相关的东西
     * OpenID connect 1.0 认证服务器信息地址 项目路径 + /.well-known/openid-configuration
     * 引用 OidcProviderConfigurationEndpointFilter
     * @return securityFilterChain
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationSecurityFilterChain(@NotNull HttpSecurity httpSecurity) throws Exception {
        // 初始 security server 配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                // 开启 OpenID Connect 1.0 == oidc
                .oidc(Customizer.withDefaults());

        httpSecurity
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer.defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer ->
                        httpSecurityOAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults())
                );

        return httpSecurity.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(@NotNull HttpSecurity httpSecurity) throws Exception {
        // security 配置
        return httpSecurity
//                .userDetailsService(userService)
                // http 拦截
                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                // 放行 /login
//                                .requestMatchers("/authorization/login").anonymous()
//                                .requestMatchers("/**").hasRole("USER")
                                .anyRequest().authenticated())
                // http 认证方式
//                .httpBasic(Customizer.withDefaults())
                // form login
                .formLogin(Customizer.withDefaults())
                // 禁用 csrf
//                .csrf(AbstractHttpConfigurer::disable)
//                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
//                        httpSecurityExceptionHandlingConfigurer
//                                .accessDeniedHandler(accessDeniedSecurityHandler)
//                                .authenticationEntryPoint(authenticationSecurityEntryPoint))
//                .addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * org.springframework.security.oauth2.server.authorization 持久化
     * @return registeredClientRepository
     */
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                // 密文
//                .clientSecret("$2a$10$WMkKx7wwlAwegIOU3MHFfuo9lemdGp380FB12rJ3Sis89V8IA3GiK")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantTypes(authorizationGrantTypes ->
//                        authorizationGrantTypes.addAll(List.of(
//                                AuthorizationGrantType.AUTHORIZATION_CODE,
//                                AuthorizationGrantType.REFRESH_TOKEN
//                        )
//                    )
//                )
//                .redirectUri("http://www.baidu.com")
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                .scopes(strings ->
//                        strings.addAll(List.of(
//                                OidcScopes.OPENID,
//                                OidcScopes.PROFILE
//                        )
//                    )
//                )
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }

    /**
     * 客户端信息
     * 对应表：oauth2_registered_client
     * @return registeredClientRepository
     */
    @Bean
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * 授权信息
     * 对应表：oauth2_authorization
     * @return auth2AuthorizationService
     */
    @Bean
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public OAuth2AuthorizationService auth2AuthorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);

        JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper oAuth2AuthorizationRowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(
                registeredClientRepository
        );

        oAuth2AuthorizationRowMapper.setLobHandler(new DefaultLobHandler());

        ObjectMapper objectMapper = new ObjectMapper();
        ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
        List<Module> moduleList = SecurityJackson2Modules.getModules(classLoader);

        objectMapper.registerModules(moduleList);
        objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());

        // User 自定义序列化
        objectMapper.addMixIn(User.class, UserMixin.class);

        oAuth2AuthorizationRowMapper.setObjectMapper(objectMapper);
        jdbcOAuth2AuthorizationService.setAuthorizationRowMapper(oAuth2AuthorizationRowMapper);
        return jdbcOAuth2AuthorizationService;
    }

    /**
     * 授权确认
     * 对应表：oauth2_authorization_consent
     * @return oAuth2AuthorizationConsentService
     */
    @Bean
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 配置 JWK，为 JWT(id_token) 提供加密密钥，用于加密/解密或签名/验签
     * JWK 详细见：https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-key-41
     * @return jwkSource
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成RSA密钥对，给上面 jwkSource() 方法的提供密钥对
     * @return keyPair
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 配置 jwt 解析器
     * @return jwtDecoder
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 配置认证服务器请求地址
     * @return authorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

}
