package com.finance.user.controller;

import com.finance.user.config.JwtUtil;
import com.finance.user.dto.AuthRequest;
import com.finance.user.dto.AuthResponse;
import com.finance.user.dto.RegisterRequest;
import com.finance.user.model.User;
import com.finance.user.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        try {
            User u = userService.register(req.getEmail(), req.getPassword(), req.getFullName());
            String token = jwtUtil.generateToken(u.getId(), u.getEmail());
            return ResponseEntity.ok(new AuthResponse(token));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(ex.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest req) {
        Optional<User> userOpt = userService.findByEmail(req.getEmail());
        if (userOpt.isEmpty()) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
        User u = userOpt.get();
        if (!passwordEncoder.matches(req.getPassword(), u.getPasswordHash())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
        String token = jwtUtil.generateToken(u.getId(), u.getEmail());
        return ResponseEntity.ok(new AuthResponse(token));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Note: JwtAuthFilter already sets Authentication principal to UUID userId
        // For a simple quick endpoint we parse token again (or we can use SecurityContextHolder)
        return ResponseEntity.ok("Use /api/users/me endpoint from user-service (later).");
    }
}
