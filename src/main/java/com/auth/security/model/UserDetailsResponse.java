package com.auth.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class UserDetailsResponse {
    private String username;
    private String encodedPassword;
    private List<String> authorities;
}
