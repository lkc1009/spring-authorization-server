package com.lkc1009.password.message;

import com.lkc1009.password.constant.OAuth2Constant;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class MobileGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    public MobileGrantAuthenticationToken(Authentication authentication, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(OAuth2Constant.GRANT_TYPE_MOBILE),
                authentication, additionalParameters);
    }
}
