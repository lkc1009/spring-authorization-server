//package com.lkc1009.authorization.handler;
//
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.web.AuthenticationEntryPoint;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//
//@Component
//public class AuthenticationSecurityEntryPoint implements AuthenticationEntryPoint {
//    @Override
//    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
//        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
//        response.setContentType("application/json;charset=utf-8");
//        response.getWriter().write("{\"code\":401,\"msg\":\"未认证\"}");
//        response.getWriter().flush();
//        response.getWriter().close();
//    }
//}
