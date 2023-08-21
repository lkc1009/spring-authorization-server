package com.lkc1009.authorization.user;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.util.Objects;
import java.util.Set;

public class UserDeserializer extends JsonDeserializer<User> {

    private static final TypeReference<Set<SimpleGrantedAuthority>> SIMPLE_GRANTED_AUTHORITY_SET = new TypeReference<>() {};

    @Override
    public User deserialize(JsonParser p, DeserializationContext deserializationContext) throws IOException {
        ObjectMapper objectMapper = (ObjectMapper) p.getCodec();
        JsonNode jsonNode = objectMapper.readTree(p);

        Set<? extends GrantedAuthority> authorities = objectMapper.convertValue(jsonNode.get("authorities"), SIMPLE_GRANTED_AUTHORITY_SET);
        JsonNode passwordNode = jsonNode(jsonNode,  "password");

        String username = jsonNode(jsonNode, "username").asText();
        String password = passwordNode.asText("");

        boolean enabled = jsonNode(jsonNode, "enabled").asBoolean();
        boolean accountNonExpired = jsonNode(jsonNode, "accountNonExpired").asBoolean();
        boolean credentialsNonExpired = jsonNode(jsonNode, "credentialsNonExpired").asBoolean();
        boolean accountNonLocked = jsonNode(jsonNode, "accountNonLocked").asBoolean();

        User user = new User(username, password, authorities);
        if (Objects.isNull(passwordNode.asText(null))) {
            user.setPassword(null);
        }
        return user;
    }

    private JsonNode jsonNode(@NotNull JsonNode jsonNode, String field) {
        return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
    }
}
