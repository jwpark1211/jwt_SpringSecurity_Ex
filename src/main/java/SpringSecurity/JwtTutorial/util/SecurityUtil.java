package SpringSecurity.JwtTutorial.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
/*
 * Jwt에서 SecurityConfig에 세팅한 유저 정보를 꺼냅니다.
 * 본 코드에선 memberId를 저장했으므로 Long 타입으로 파싱하여 반환합니다.
 * SecurityContext는  ThreadLocal에 사용자의 정보를 저장합니다.
 */
public class SecurityUtil {
    private SecurityUtil() { }

    // SecurityContext 에 유저 정보가 저장되는 시점
    // Request 가 들어올 때 JwtFilter 의 doFilter 에서 저장
    public static Long getCurrentMemberId() {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw  new RuntimeException("Security Context 에 인증 정보가 없습니다.");
        }

        return Long.parseLong(authentication.getName());
    }

}
