package SpringSecurity.JwtTutorial.Entity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@NoArgsConstructor
@Table(name = "member")
@Entity
// Spring Security 자체적으로 UserDetails의 구현체인 User를 사용하기 때문에
// User는 가급적 사용하지 않는 것이 좋다.
public class Member {

    @Id @GeneratedValue
    @Column(name = "member_id")
    private Long id;
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Authority authority;

    @Builder
    public Member(String email, String password, Authority authority) {
        this.email = email;
        this.password = password;
        this.authority = authority;
    }
}
