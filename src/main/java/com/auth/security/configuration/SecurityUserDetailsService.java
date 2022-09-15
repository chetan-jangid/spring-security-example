package com.auth.security.configuration;

import com.auth.security.model.UserAccount;
import com.auth.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class SecurityUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAccount userAccount = userRepository.findByUsername(username);
        if (Objects.isNull(userAccount)) {
            throw new UsernameNotFoundException("No user found with username: " + username + ".");
        }
        return new User(userAccount.getUsername(), userAccount.getPassword(), userAccount.getRoles()
                .stream().map(SimpleGrantedAuthority::new).toList());
    }
}
