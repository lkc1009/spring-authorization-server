//package com.lkc1009.authorization;
//
//import com.lkc1009.authorization.user.UserService;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.jetbrains.annotations.NotNull;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.Objects;
//
///**
// * 自定义用户认证
// */
////@Slf4j
////@RequiredArgsConstructor
////public class DaoAuthenticationProvider implements AuthenticationProvider {
////    private final UserService userService;
////    private final PasswordEncoder passwordEncoder;
////
////    @Override
////    public Authentication authenticate(@NotNull Authentication authentication) throws AuthenticationException {
////        log.info("DaoAuthenticationFilter 认证");
////        // 获取用户名和密码
////        String username = authentication.getName();
////        String password = authentication.getCredentials().toString();
////
////        log.info("DaoAuthenticationFilter 认证 username:{} password:{}", username, password);
////
////        UserDetails userDetails = userService.loadUserByUsername(username);
////
////        if (Objects.isNull(userDetails)) {
////            throw new UsernameNotFoundException("用户名不存在");
////        }
////
////        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
////            throw new BadCredentialsException("密码错误");
////        }
////
////        return new UsernamePasswordAuthenticationToken(userDetails, password, userDetails.getAuthorities());
////    }
////
////    @Override
////    public boolean supports(@NotNull Class<?> authentication) {
////        return authentication.equals(UsernamePasswordAuthenticationToken.class);
////    }
////}
