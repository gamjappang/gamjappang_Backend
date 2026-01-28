package demago.gamjappang.dto.common;

import java.time.Instant;
import java.util.List;

public record ErrorResponse(
        Instant timestamp,
        int status,
        String code,
        String message,
        String path,
        List<FieldErrorItem> fieldErrors
) {
    public record FieldErrorItem(String field, String reason) {}
}