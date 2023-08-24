package com.lkc1009.password.oidc;

import com.lkc1009.password.user.oidc.OidcUserInfo;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

@RequiredArgsConstructor
public class OidcUserInfoAuthenticationConverter implements AuthenticationConverter {
    private final OidcUserInfoService oidcUserInfoService;

    @Override
    public Authentication convert(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        OidcUserInfo oidcUserInfo = oidcUserInfoService.loadUser(authentication.getName());
        return new OidcUserInfoAuthenticationToken(authentication, oidcUserInfo);
    }
}
