package demago.gamjappang.config.oauth.provider;

import java.util.HashMap;
import java.util.Map;

public class KakaoUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attributes;

    public KakaoUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return attributes.get("id").toString();
    }

    @Override
    public String getProvider() {
        return "kakao";
    }

    @Override
    public String getName() {
        HashMap properties = (HashMap)attributes.get("properties");
        return properties.get("nickname").toString();
    }

    @Override
    public String getEmail() {
//        System.out.println("attribute: " + attributes.get("email"));
//        System.out.println("attribute: " + attributes.get("nickname"));

       return attributes.get("email") == null ? getName() + "@email.com" : attributes.get("email").toString();

                //"email.com" + attributes.get("id").toString();
    }
}