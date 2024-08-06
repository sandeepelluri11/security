package com.spring.security.service;

import com.spring.security.dto.AuthenticateRequest;
import com.spring.security.dto.AuthenticationResponse;
import com.spring.security.dto.RegisterRequest;
import com.spring.security.jwt.JwtService;
import com.spring.security.model.Role;
import com.spring.security.model.User;
import com.spring.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(Role.valueOf(request.getRole()))
                .build();
        userRepository.save(user);

        String token = jwtService.generateToken(new HashMap<>(),user);

        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticateRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByUsername(request.getUsername());
        String token = jwtService.generateToken(new HashMap<>(),user);

        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }
}
