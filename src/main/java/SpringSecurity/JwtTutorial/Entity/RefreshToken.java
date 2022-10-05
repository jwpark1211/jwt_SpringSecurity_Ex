package SpringSecurity.JwtTutorial.Entity;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Getter
@NoArgsConstructor
@Table(name = "refresh_token")
@Entity
public class RefreshToken {

    /*
     * key 에는 member id 값이 들어간다.
     * value에는 Refresh Token String이 들어간다.
     * RDB를 사용한다면 생성/수정 시간 컬럼을 추가하여 배치 작업으로 만료된 토큰들을 사용해주어야 한다.
     * 위의 과정을 생략하기 위하여 보통 REDIS를 사용한다.
    */
    @Id @Column(name = "rt_key")
    private String key;

    @Column(name = "rt_value")
    private String value;

    @Builder
    public RefreshToken(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public RefreshToken updateValue(String token) {
        this.value = token;
        return this;
    }
}
