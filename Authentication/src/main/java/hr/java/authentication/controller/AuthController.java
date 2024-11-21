package hr.java.authentication.controller;

import hr.java.authentication.model.RefreshToken;
import hr.java.authentication.model.Role;
import hr.java.authentication.model.UserInfo;
import hr.java.authentication.model.enums.ERole;
import hr.java.authentication.payload.request.LoginRequest;
import hr.java.authentication.payload.request.RefreshTokenRequest;
import hr.java.authentication.payload.request.RegistrationRequest;
import hr.java.authentication.payload.response.JwtResponse;
import hr.java.authentication.repository.RoleRepository;
import hr.java.authentication.repository.UserRepository;
import hr.java.authentication.security.jwt.JwtService;
import hr.java.authentication.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Set;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    JwtService jwtService;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegistrationRequest registrationRequest) {
        if (userRepository.existsByUsername(registrationRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username is already taken!");
        }

        if (userRepository.existsByEmail(registrationRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        Set<Role> basicRoles = new HashSet<>();
        basicRoles.add(new Role(ERole.valueOf("ROLE_USER")));

        UserInfo user = new UserInfo(
                registrationRequest.getUsername(),
                registrationRequest.getEmail(),
                registrationRequest.getPassword(),
                basicRoles
        );

        userRepository.save(user);

        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(), loginRequest.getPassword())
                );

        if (authentication.isAuthenticated()) {
            RefreshToken refreshToken = refreshTokenService.createRefreshToken(loginRequest.getUsername());
            return ResponseEntity.ok().body(
                    JwtResponse.builder()
                            .accessToken(jwtService.generateToken(loginRequest.getUsername()))
                            .token(refreshToken.getToken())
                            .build());
        } else {
            throw new UsernameNotFoundException("Invalid user request!");
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser() {
        return ResponseEntity.ok().body("You've been signed out!");
    }

    @PostMapping("/refreshToken")
    public JwtResponse refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest){
        return refreshTokenService.findByToken(refreshTokenRequest.getToken())
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(userInfo -> {
                    String accessToken = jwtService.generateToken(userInfo.getUsername());
                    return JwtResponse.builder()
                            .accessToken(accessToken)
                            .token(refreshTokenRequest.getToken()).build();
                }).orElseThrow(() -> new RuntimeException("Refresh Token is not in database!"));
    }

}
