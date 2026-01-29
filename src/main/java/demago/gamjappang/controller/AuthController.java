package demago.gamjappang.controller;

import demago.gamjappang.dto.auth.LoginRequest;
import demago.gamjappang.dto.auth.JoinRequest;
import demago.gamjappang.dto.auth.verityRequest;
import demago.gamjappang.model.User;
import demago.gamjappang.service.UserService;
import demago.gamjappang.jwt.JwtTokenProvider;
import demago.gamjappang.config.auth.PrincipalDetails;
import demago.gamjappang.service.MailService;

import jakarta.mail.MessagingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    private final AuthenticationManager authenticationManager;

    private final JwtTokenProvider jwtTokenProvider;

    private final MailService mailService;

    @Autowired
    public AuthController(UserService userService,
                          AuthenticationManager authenticationManager,
                          JwtTokenProvider jwtTokenProvider,
                          MailService mailService) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.mailService = mailService;
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody JoinRequest request) throws MessagingException {
        User saved = userService.registerLocalUser(request.toEntity());
        String email = saved.getEmail();

        boolean isSend = mailService.sendSimpleMessage(email);
        if (isSend) {
            System.out.println("인증 코드가 전송되었습니다.");
        } else {
            System.out.println("인증 코드 발급에 실패하였습니다.");
        }

        return ResponseEntity.ok().body(
                java.util.Map.of(
                        "id", saved.getId(),
                        "username", saved.getUsername()
                )
        );
    }

    @PostMapping("/join/verify")
    public ResponseEntity<?> verification(@RequestBody verityRequest verityRequest) {
        String username = verityRequest.getUsername();
        String authCode = verityRequest.getAuthCode();

        User veritedUser = userService.verifyLocalUser(username, authCode);

        return ResponseEntity.ok().body(
                java.util.Map.of(
                        "id", veritedUser.getId(),
                        "username", veritedUser.getUsername()
                )
        );
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest body) {
        String username = body.username();
        String password = body.password();

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        PrincipalDetails principal = (PrincipalDetails) auth.getPrincipal();
        String role = principal.getUser().getRole();

        String access = jwtTokenProvider.createAccessToken(username, role);
        String refresh = jwtTokenProvider.createRefreshToken(username);

        ResponseCookie accessCookie = ResponseCookie.from("access_token", access)
                .httpOnly(true)
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .sameSite("Lax")
                .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh_token", refresh)
                .httpOnly(true)
                .path("/")
                .maxAge(Duration.ofDays(14))
                .sameSite("Lax")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessCookie.toString())
                .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                .body(java.util.Map.of("ok", true));
    }
}
