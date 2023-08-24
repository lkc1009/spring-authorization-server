package com.lkc1009.password.user.oidc;

import lombok.Getter;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.springframework.util.Assert;

import java.io.Serial;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

@Getter
public class OidcUserInfo extends org.springframework.security.oauth2.core.oidc.OidcUserInfo {
    @Serial
    private static final long serialVersionUID = 1L;
    private final Map<String, Object> claims;

    public OidcUserInfo(Map<String, Object> claims) {
        super(claims);
        Assert.notEmpty(claims, "claims cannot be empty");
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
    }

    @Contract(" -> new")
    public static OidcUserInfo.@NotNull Builder Builder() {
        return new OidcUserInfo.Builder();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj != null && this.getClass() == obj.getClass()) {
            OidcUserInfo oidcUserInfo = (OidcUserInfo) obj;
            return this.getClaims().equals(oidcUserInfo.getClaims());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.getClaims().hashCode();
    }

    public static final class Builder {
        private final Map<String, Object> claims = new LinkedHashMap<>();

        private Builder() {
        }

        public OidcUserInfo.Builder claim(String name, Object value) {
            this.claims.put(name, value);
            return this;
        }

        @Contract("_ -> this")
        public OidcUserInfo.Builder claims(@NotNull Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(this.claims);
            return this;
        }

        public OidcUserInfo.Builder username(String username) {
            return this.claim("username", username);
        }

        public OidcUserInfo.Builder status(Integer enabled) {
            return this.claim("enabled", enabled);
        }

        public OidcUserInfo.Builder email(String email) {
            return this.claim("email", email);
        }

        public OidcUserInfo.Builder profile(String profile) {
            return this.claim("profile", profile);
        }

        @Contract(" -> new")
        public @NotNull OidcUserInfo build() {
            return new OidcUserInfo(this.claims);
        }

    }
}
