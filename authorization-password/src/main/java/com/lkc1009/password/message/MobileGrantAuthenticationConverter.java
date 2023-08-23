package com.lkc1009.password.message;

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

public class MobileGrantAuthenticationConverter implements AuthenticationConverter {
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

    @Override
    public Authentication convert(@NotNull HttpServletRequest request) {
        // grant_type(REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!OAuth2Constant.GRANT_TYPE_MOBILE.equals(grantType)) {
            return null;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 从 request 中提取请求参数，然后存入 MultiValueMap<String, String>
        MultiValueMap<String, String> parameters = getParameters(request);

        // username(REQUIRED)
        String smsCode = parameters.getFirst(OAuth2Constant.SMS_CODE);
        if (!StringUtils.hasText(smsCode) ||
                parameters.get(OAuth2Constant.SMS_CODE).size() != 1) {
            throw new OAuth2AuthenticationException("无效请求，短信验证码不能为空！");
        }

        // 收集要传入 MobileGrantAuthenticationToken 构造方法的参数
        // 该参数接下来在 MobileGrantAuthenticationProvider 中使用
        Map<String, Object> additionalParameters = new HashMap<>();

        // 遍历从 request 中提取的参数，排除掉 grant_type、client_id、code 等字段参数，其他参数收集到 additionalParameters 中
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        // 返回自定义的 MobileGrantAuthenticationToken 对象
        return new MobileGrantAuthenticationToken(authentication, additionalParameters);
    }
}
