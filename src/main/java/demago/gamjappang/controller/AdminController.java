package demago.gamjappang.controller;

import demago.gamjappang.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final UserService memberService;

    @Autowired
    public AdminController(UserService memberService) {
        this.memberService = memberService;
    }

//    // 회원 목록 조회
//    @GetMapping
//    public
//    }
//
//    // 회원 상세 조회
//    @GetMapping("/{id}")
//    public String detail
//    }
}