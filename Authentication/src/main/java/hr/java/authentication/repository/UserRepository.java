package hr.java.authentication.repository;

import hr.java.authentication.model.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserInfo, Long> {
    Optional<UserInfo> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}