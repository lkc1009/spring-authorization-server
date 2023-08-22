package com.lkc1009.server.controller;

import com.lkc1009.server.security.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/authorization")
@RequiredArgsConstructor
public class AuthorizationController {
    private final LoginService loginService;

    @GetMapping("/success")
    public String success() {
        return "success";
    }

    @PostMapping("/login")
    public String login(String username, String password) {
        return loginService.login(username, password);
    }

    @PostMapping("/logout")
    public String logout() {
        return loginService.logout();
    }
}
