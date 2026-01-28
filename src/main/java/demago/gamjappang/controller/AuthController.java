package demago.gamjappang.controller;

import demago.gamjappang.dto.auth.JoinRequest;
import demago.gamjappang.model.User;
import demago.gamjappang.service.UserService;
import demago.gamjappang.jwt.JwtTokenProvider;

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

    @Autowired
    public AuthController(UserService userService,
                          AuthenticationManager authenticationManager,
                          JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(@RequestBody JoinRequest request) {
        User saved = userService.registerLocalUser(request.toEntity());
        return ResponseEntity.ok().body(
                java.util.Map.of(
                        "id", saved.getId(),
                        "username", saved.getUsername()
                )
        );
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody java.util.Map<String, String> body) {
        String username = body.get("username");
        String password = body.get("password");

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        var principal = (demago.gamjappang.config.auth.PrincipalDetails) auth.getPrincipal();
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
