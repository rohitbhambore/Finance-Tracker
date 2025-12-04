package com.finance.user.service;

import com.finance.user.model.User;
import com.finance.user.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    private final UserRepository repo;
    private final PasswordEncoder encoder;

    public UserService(UserRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    public User register(String email, String rawPassword, String fullName) {
        if (repo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered");
        }
        User u = new User();
        u.setEmail(email.toLowerCase().trim());
        u.setPasswordHash(encoder.encode(rawPassword));
        u.setFullName(fullName);
        return repo.save(u);
    }

    public Optional<User> findByEmail(String email) {
        return repo.findByEmail(email);
    }

    public Optional<User> findById(UUID id) {
        return repo.findById(id);
    }
}
