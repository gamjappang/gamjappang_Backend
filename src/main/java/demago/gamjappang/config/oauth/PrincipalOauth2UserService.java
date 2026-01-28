package demago.gamjappang.config.oauth;


import demago.gamjappang.config.auth.PrincipalDetails;
import demago.gamjappang.config.oauth.provider.GoogleUserInfo;
import demago.gamjappang.config.oauth.provider.KakaoUserInfo;
import demago.gamjappang.config.oauth.provider.NaverUserInfo;
import demago.gamjappang.config.oauth.provider.OAuth2UserInfo;
import demago.gamjappang.model.User;
import demago.gamjappang.service.UserService;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserService userService;

    public PrincipalOauth2UserService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo userInfo;
        if ("google".equals(registrationId)) {
            userInfo = new GoogleUserInfo(oauth2User.getAttributes());
        } else if ("kakao".equals(registrationId)) {
            userInfo = new KakaoUserInfo(oauth2User.getAttributes());
        } else if ("naver".equals(registrationId)) {
            userInfo = new NaverUserInfo((Map<String, Object>) oauth2User.getAttributes().get("response"));
        } else {
            throw new OAuth2AuthenticationException("지원하지 않는 프로바이더: " + registrationId);
        }

        User userEntity = userService.findOrCreateOAuthUser(userInfo);

        return new PrincipalDetails(userEntity, oauth2User.getAttributes());
    }
}
