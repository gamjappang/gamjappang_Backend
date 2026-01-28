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
}
