package com.lkc1009.authorization.security;

import com.lkc1009.authorization.DaoAuthenticationProvider;
import com.lkc1009.authorization.user.User;
import com.lkc1009.authorization.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * 自定义登录逻辑
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public String login(String username, String password) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userService, passwordEncoder);

        Authentication authentication = daoAuthenticationProvider.authenticate(usernamePasswordAuthenticationToken);

        if (Objects.isNull(authentication)) {
            return "用户名或密码错误";
        }

        User user = (User) authentication.getPrincipal();
        return user.getUsername();
    }
}
