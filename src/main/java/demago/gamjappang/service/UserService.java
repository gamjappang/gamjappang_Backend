package demago.gamjappang.service;

import demago.gamjappang.config.oauth.provider.OAuth2UserInfo;
import demago.gamjappang.model.User;
import demago.gamjappang.rapository.UserRepository;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 일반 회원가입
    @Transactional
    public User registerLocalUser(User user) {
        user.setRole("ROLE_USER");

        if (user.getPassword() != null && !user.getPassword().isBlank()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }

        return userRepository.save(user);
    }

    // OAuth 로그인 시 provider/providerId 기반으로 찾고 없으면 생성
    @Transactional
    public User findOrCreateOAuthUser(OAuth2UserInfo userInfo) {
        String provider = userInfo.getProvider();
        String providerId = userInfo.getProviderId();
        String username = provider + "-" + providerId;

        User userEntity = userRepository.findByUsername(username);
        if (userEntity != null) {
            return userEntity;
        }

        User newUser = User.builder()
                .username(username)
                .password(null) // 소셜 로그인은 비번 불필요
                .email(userInfo.getEmail())
                .role("ROLE_USER")
                .provider(provider)
                .providerId(providerId)
                .build();

        return userRepository.save(newUser);
    }
}
