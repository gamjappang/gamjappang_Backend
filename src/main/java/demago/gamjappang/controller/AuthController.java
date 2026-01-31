package demago.gamjappang.controller;

import demago.gamjappang.config.auth.PrincipalDetails;
import demago.gamjappang.dto.auth.JoinRequest;
import demago.gamjappang.dto.auth.LoginRequest;
import demago.gamjappang.dto.auth.LoginResponse;
import demago.gamjappang.dto.auth.RefreshRequest;
import demago.gamjappang.dto.auth.verityRequest;
import demago.gamjappang.jwt.JwtTokenProvider;
import demago.gamjappang.model.User;
import demago.gamjappang.rapository.UserRepository;
import demago.gamjappang.service.MailService;
import demago.gamjappang.service.UserService;
import jakarta.mail.MessagingException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final UserRepository userRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final MailService mailService;

    public AuthController(
            UserService userService,
            UserRepository userRepository,
            AuthenticationManager authenticationManager,
            JwtTokenProvider jwtTokenProvider,
            MailService mailService
    ) {
        this.userService = userService;
        this.userRepository = userRepository;
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

        User verifiedUser = userService.verifyLocalUser(username, authCode);
        if (verifiedUser == null) {
            return ResponseEntity.badRequest().body(java.util.Map.of(
                    "ok", false,
                    "message", "인증 코드가 올바르지 않습니다."
            ));
        }

        return ResponseEntity.ok().body(
                java.util.Map.of(
                        "id", verifiedUser.getId(),
                        "username", verifiedUser.getUsername()
                )
        );
    }

    // JWT 로그인 Bearer 방식
    // accessToken: 프론트에서 Authorization: Bearer {token} 으로 전송
    // refreshToken: access 만료 시 /refresh 로 보내서 access 재발급
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest body) {
        String username = body.username();
        String password = body.password();

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        PrincipalDetails principal = (PrincipalDetails) auth.getPrincipal();
        String role = principal.getUser().getRole();

        String access = jwtTokenProvider.createAccessToken(username, role);
        String refresh = jwtTokenProvider.createRefreshToken(username);

        return ResponseEntity.ok(new LoginResponse(access, refresh));
    }

    // refreshToken으로 accessToken 재발급
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest body) {
        String refreshToken = body.refreshToken();

        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body(java.util.Map.of(
                    "ok", false,
                    "message", "refreshToken이 필요합니다."
            ));
        }

        if (!jwtTokenProvider.validate(refreshToken)) {
            return ResponseEntity.status(401).body(java.util.Map.of(
                    "ok", false,
                    "message", "refreshToken이 유효하지 않습니다."
            ));
        }

        String username = jwtTokenProvider.getUsername(refreshToken);
        User user = userRepository.findByUsername(username);
        if (user == null) {
            return ResponseEntity.status(401).body(java.util.Map.of(
                    "ok", false,
                    "message", "사용자를 찾을 수 없습니다."
            ));
        }

        String newAccess = jwtTokenProvider.createAccessToken(username, user.getRole());
        return ResponseEntity.ok(java.util.Map.of(
                "accessToken", newAccess
        ));
    }
}
