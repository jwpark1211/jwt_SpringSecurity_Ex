package SpringSecurity.JwtTutorial.Repository;

import SpringSecurity.JwtTutorial.Entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByKey(String key); //MemberId값으로 Token을 가져옴.
}
