package com.auth.security.service;

import com.auth.security.model.UserDetailsResponse;
import com.auth.security.repository.exception.AuthException;

public interface AuthenticationService {
    UserDetailsResponse getUserDetails();

    String getUsername() throws AuthException;

    String generateNewEncodedToken(String token) throws AuthException;

    String generateToken(String subject) throws AuthException;

    String getToken();
}
