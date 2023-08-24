package com.lkc1009.password.oidc;

import com.lkc1009.password.user.User;
import com.lkc1009.password.user.UserService;
import com.lkc1009.password.user.oidc.OidcUserInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OidcUserInfoService {
    private final UserService userService;

    public OidcUserInfo loadUser(String username) {
        return new OidcUserInfo(this.createUser((User) userService.loadUserByUsername(username)));
    }

    private Map<String, Object> createUser(@NotNull User user) {
        return OidcUserInfo
                .Builder()
                .username(user.getUsername())
                .status(1)
                .email("123@123.com")
                .profile("test.com")
                .build()
                .getClaims();
    }

}
