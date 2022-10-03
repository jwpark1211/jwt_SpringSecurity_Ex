package SpringSecurity.JwtTutorial.Service;

import SpringSecurity.JwtTutorial.Controller.Dto.MemberResponseDto;
import SpringSecurity.JwtTutorial.Repository.MemberRepository;
import SpringSecurity.JwtTutorial.util.SecurityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;

    @Transactional(readOnly = true)
    public MemberResponseDto getMemberInfo(String email){
        return memberRepository.findByEmail(email) //email로 member 유저 정보를 찾아서
                .map(MemberResponseDto::of) //member를 memberResponseDto로 변환한다.
                .orElseThrow(()-> new RuntimeException("유저 정보가 없습니다.")); //유저 정보가 없으면 RunTime예외를 발생
    }

    // 현재 SecurityContext 에 있는 유저 정보 가져오기
    @Transactional(readOnly = true)
    public MemberResponseDto getMyInfo() {
        return memberRepository.findById(SecurityUtil.getCurrentMemberId())
                .map(MemberResponseDto::of)
                .orElseThrow(() -> new RuntimeException("로그인 유저 정보가 없습니다."));
    }

    /*
     * 내 정보를 가져올 때는 SecurityUtil.getCurrentMemberId()를 사용합니다.
     * API 요청이 들어오면 필터에서 Access Token을 복호화하여 유저 정보를 꺼내 SecurityContext에 저장합니다.
     * SecurityContext에 저장된 유저 정보는 전역으로 언제든 꺼내올 수 있습니다.
     * SecurityUtil 클래스에서는 유저 정보에서 MemberId만 반환하는 메소드가 정의되어 있습니다.
     */
}
