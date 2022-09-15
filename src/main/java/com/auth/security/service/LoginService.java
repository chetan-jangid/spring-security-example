package com.auth.security.service;

import com.auth.security.model.AuthenticationDetails;
import com.auth.security.model.AuthenticationToken;

public interface LoginService {
    AuthenticationToken authenticate(AuthenticationDetails details);
}
