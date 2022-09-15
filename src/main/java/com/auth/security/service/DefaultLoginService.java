package com.auth.security.service;

import com.auth.security.model.AuthenticationDetails;
import com.auth.security.model.AuthenticationToken;
import com.auth.security.model.UserAccount;
import com.auth.security.repository.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class DefaultLoginService implements LoginService {
    private final AuthenticationManager authenticationManager;
    private final AuthenticationService authenticationService;

    @Override
    public AuthenticationToken authenticate(AuthenticationDetails details) throws AuthException {
        Objects.requireNonNull(details, () -> {
            throw new BadCredentialsException("Invalid request.");
        });
        User principal = getAuthentication(details.getUsername(), details.getPassword());
        String token = generateToken(principal);
        return new AuthenticationToken(token);
    }

    private String generateToken(User principal) {
        return authenticationService.generateToken(principal.getUsername());
    }

    private User getAuthentication(String username, String password) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(username, password));
        return (User) authentication.getPrincipal();
    }
}
