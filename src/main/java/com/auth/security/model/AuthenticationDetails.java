package com.auth.security.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthenticationDetails {
    private String username;
    private String password;
}
