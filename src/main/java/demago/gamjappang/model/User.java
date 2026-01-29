package demago.gamjappang.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Table(name = "users")
@Getter @Setter
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    private String password;

    private String email;

    private String role;

    private String imageUrl;

//    private Timestamp lastLogin;

    private String provider;
    private String providerId;

    private boolean verified;

    @CreationTimestamp
    private java.time.LocalDateTime createdDate;

    private String authCode;

    public void Auth(String email, String authCode){
        this.email = email;
        this.authCode = authCode;
    }

    public void patch(String authCode){
        this.authCode = authCode;
    }

    @Builder
    public User(Long id, String username, String password, String email, String role, String provider, String providerId, String imageUrl) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.imageUrl = imageUrl;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
    }
}