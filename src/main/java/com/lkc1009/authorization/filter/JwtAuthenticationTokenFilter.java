package com.lkc1009.authorization.filter;

import com.lkc1009.authorization.user.User;
import com.lkc1009.authorization.user.UserService;
import com.lkc1009.authorization.util.JwtUtils;
import io.jsonwebtoken.Claims;
import io.micrometer.common.util.StringUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Date;
import java.util.Objects;

/**
 * BasicAuthenticationFilter处理UsernamePasswordAuthenticationToken
 * 模拟BasicAuthenticationFilter
 * 创建JwtAuthenticationTokenFilter处理用户认证Token信息
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final UserService userService;

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, @NotNull FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("token");

        if (StringUtils.isBlank(token)) {
            filterChain.doFilter(request, response);
            return;
        }

        String username;

        Claims claims = JwtUtils.parseJwtToken(token, JwtUtils.base64EncodedSecretKey);
        Date date = new Date();
        if (date.getTime() > claims.getExpiration().getTime()) {
            log.error("Token已过期");
            throw new RuntimeException("Token已过期");
        }

        username = claims.getSubject();

        User user = (User) userService.loadUserByUsername(username);

        if (Objects.isNull(user)) {
            log.error("用户不存在");
            throw new RuntimeException("用户不存在");
        }

    }
}