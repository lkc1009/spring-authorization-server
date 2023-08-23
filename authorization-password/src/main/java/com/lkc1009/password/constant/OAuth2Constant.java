package com.lkc1009.password.constant;

public class OAuth2Constant {

    /**
     * 密码模式（自定义）
     */
    public static final String GRANT_TYPE_PASSWORD = "authorization_password";


    /**
     * 构造方法私有化
     */
    private OAuth2Constant(){

    }

    /**
     * 短信验证码模式（自定义）
     */
    public static final String GRANT_TYPE_MOBILE = "authorization_mobile";

    /**
     * 短信验证码
     */
    public static final String SMS_CODE = "sms_code";

    /**
     * 短信验证码默认值
     */
    public static final String SMS_CODE_VALUE = "8888";
}