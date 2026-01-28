package demago.gamjappang.dto.auth;

public record LoginRequest(
        String username,
        String password
) {}