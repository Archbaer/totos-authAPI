package com.authAPI.authAPI.services;

import com.authAPI.authAPI.models.User;
import com.authAPI.authAPI.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public void register(User user) {
        if (userRepository.count() == 0) {
            user.setRole("ADMIN"); // First user is admin
        } else {
            user.setRole("USER");
        }
        // Encode the password before saving
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

}
