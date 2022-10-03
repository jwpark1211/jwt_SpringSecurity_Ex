package SpringSecurity.JwtTutorial.Controller;

import SpringSecurity.JwtTutorial.Controller.Dto.MemberResponseDto;
import SpringSecurity.JwtTutorial.Repository.MemberRepository;
import SpringSecurity.JwtTutorial.Service.MemberService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/member")
public class MemberController {
    private final MemberService memberService;

    @GetMapping("/me")
    public ResponseEntity<MemberResponseDto> getMyMemberInfo(){
        return ResponseEntity.ok(memberService.getMyInfo());
    }

    @GetMapping("/{email}")
    public ResponseEntity<MemberResponseDto> getMemberInfo(@PathVariable String email){
        return ResponseEntity.ok(memberService.getMemberInfo(email));
    }
}