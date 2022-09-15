package com.auth.security.repository;

import com.auth.security.model.UserAccount;

public interface UserRepository {
    UserAccount findByUsername(String username);
}
