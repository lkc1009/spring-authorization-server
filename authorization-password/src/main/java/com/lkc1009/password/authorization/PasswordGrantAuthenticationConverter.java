package com.lkc1009.password.authorization;

import com.lkc1009.password.constant.OAuth2Constant;
import jakarta.servlet.http.HttpServletRequest;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class PasswordGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(@NotNull HttpServletRequest httpServletRequest) {
        String grantType = httpServletRequest.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!OAuth2Constant.GRANT_TYPE_PASSWORD.equals(grantType)) {
            return null;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 从 request 中提取请求参数，然后存入 MultiValueMap<String, String>
        MultiValueMap<String, String> parameters = getParameters(httpServletRequest);

        // username(REQUIRED)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            throw new OAuth2AuthenticationException("username must be supplied");
        }

        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            throw new OAuth2AuthenticationException("password must be supplied");
        }

        // 收集要传入 PasswordGrantAuthenticationToken 构造方法的参数
        // 该参数接下来在 PasswordGrantAuthenticationProvider 中使用
        Map<String, Object> additionalParameters = new HashMap<>();

        // 遍历从 request 中提取的参数，排除掉 grant_type、client_id、code 等字段参数，其他参数收集到 additionalParameters 中
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                && !key.equals(OAuth2ParameterNames.CLIENT_ID)
                && !key.equals(OAuth2ParameterNames.CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        // 返回自定义的 PasswordGrantAuthenticationToken 对象
        return new PasswordGrantAuthenticationToken(authentication, additionalParameters);
    }

    private static @NotNull MultiValueMap<String, String> getParameters(@NotNull HttpServletRequest httpServletRequest) {
        Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());

        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });
        return parameters;
    }
}
