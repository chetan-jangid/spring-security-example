package com.auth.security.repository;

import com.auth.security.model.UserAccount;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class DefaultUserRepository implements UserRepository {
    private static final String DEFAULT_PASSWORD = "$2a$10$Dv8XfQVzVjLI21evwgq5we3I3co9rZMHRSTEauKs2PqgvbveE9Ztu";

    /**
     * The UserAccount should be ideally returned from database. We are using pre-defined users for learning purposes.
     * @param username Username/email of the user
     * @return UserAccount
     */
    @Override
    public UserAccount findByUsername(String username) {
        return findAllUsers().stream()
                .filter(userAccount -> userAccount.getUsername().equals(username))
                .findFirst().orElse(null);
    }

    private List<UserAccount> findAllUsers() {
        return List.of(
                new UserAccount("user1", DEFAULT_PASSWORD, List.of("admin")),
                new UserAccount("user2", DEFAULT_PASSWORD, List.of("user"))
        );
    }
}
