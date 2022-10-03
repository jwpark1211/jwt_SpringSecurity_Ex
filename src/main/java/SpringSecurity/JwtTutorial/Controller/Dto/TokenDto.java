package SpringSecurity.JwtTutorial.Controller.Dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TokenDto {

    private String  grantType; //허가를 받는 유형
    private String accessToken;
    private String refreshToken;
    private Long accessTokenExpiresIn; //access Token 제한 시간
}
