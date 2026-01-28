package demago.gamjappang.controller;

import demago.gamjappang.dto.auth.JoinRequest;
import demago.gamjappang.model.User;
import demago.gamjappang.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
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
}
