package com.lkc1009.authorization.user;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 自定义用户验证
 */
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {
    private final UserMapper userMapper;
    private final AuthoritiesMapper authoritiesMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.selectOne(new LambdaQueryWrapper<User>()
                .eq(User::getUsername, username));

        if (Objects.isNull(user)) {
            throw new RuntimeException("用户名不存在");
        }

        Set<Authorities> authoritiesSet = Set.copyOf(authoritiesMapper.selectList(new LambdaQueryWrapper<Authorities>()
                .eq(Authorities::getUsername, username)));

        if (authoritiesSet.isEmpty()) {
            throw new RuntimeException("用户没有权限");
        }

        user.setRoles(authoritiesSet.stream().map(Authorities::getAuthority).collect(Collectors.toSet()));
        return user;
    }
}