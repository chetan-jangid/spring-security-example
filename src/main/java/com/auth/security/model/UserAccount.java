package com.auth.security.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@AllArgsConstructor
public class UserAccount {
    private String username;
    private String password;
    private List<String> roles;
}
