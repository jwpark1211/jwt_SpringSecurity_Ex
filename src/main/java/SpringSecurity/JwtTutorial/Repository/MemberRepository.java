package SpringSecurity.JwtTutorial.Repository;

import SpringSecurity.JwtTutorial.Entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member,Long> {
    Optional<Member> findByEmail(String email);
    boolean existsByEmail(String email);
    // existsByEmail = 중복 가입 방지
}
