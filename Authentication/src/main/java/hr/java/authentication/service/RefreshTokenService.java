package hr.java.authentication.service;

import hr.java.authentication.model.RefreshToken;
import hr.java.authentication.repository.RefreshTokenRepository;
import hr.java.authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    @Autowired
    RefreshTokenRepository refreshTokenRepository;
    @Autowired
    UserRepository userRepository;

    public RefreshToken createRefreshToken(String username) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(userRepository.findByUsername(username).get())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(600000))
                .build();

        Optional<RefreshToken> existingToken = findByToken(refreshToken.getToken());
        if (existingToken.isPresent()) {
            existingToken.get().setExpiryDate(refreshToken.getExpiryDate());
            existingToken.get().setUser(refreshToken.getUser());

            refreshTokenRepository.delete(existingToken.get());

            return refreshTokenRepository.save(existingToken.get());
        } else {
            return refreshTokenRepository.save(refreshToken);
        }
    }

    public Optional<RefreshToken> findByToken(String token){
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token){
        if(token.getExpiryDate().compareTo(Instant.now())<0){
            refreshTokenRepository.delete(token);
            throw new RuntimeException(token.getToken() + " Refresh token is expired. Please make a new login..!");
        }
        return token;
    }

}
