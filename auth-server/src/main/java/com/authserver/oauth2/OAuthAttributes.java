package com.authserver.oauth2;

import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Builder
@Getter
public class OAuthAttributes {
    private Map<String, Object> attributes;     // OAuth2 반환하는 유저 정보
    private String nameAttributesKey;
    private String id;
    private String name;
    private String email;
    private String gender;
    private String ageRange;
    private String profileImageUrl;


    public static OAuthAttributes of(String socialName, Map<String, Object> attributes) {
        if ("kakao".equals(socialName)) {
            return ofKakao("id", attributes);
        } else if ("google".equals(socialName)) {
            return ofGoogle("sub", attributes);
        } else if ("naver".equals(socialName)) {
            return ofNaver("id", attributes);
        } else {
            throw new GlobalException(ResponseCode.NOT_SUPPORTED_SOCIAL);
        }
    }

    private static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return OAuthAttributes.builder()
                .id(String.valueOf(attributes.get("sub")))
                .name(String.valueOf(attributes.get("name")))
                .email(String.valueOf(attributes.get("email")))
                .profileImageUrl(String.valueOf(attributes.get("picture")))
                .attributes(attributes)
                .nameAttributesKey(userNameAttributeName)
                .build();
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> kakaoProfile = (Map<String, Object>) kakaoAccount.get("profile");

        return OAuthAttributes.builder()
                .id(String.valueOf(attributes.get("id")))
                .name(String.valueOf(kakaoProfile.get("nickname")))
                .email(String.valueOf(kakaoAccount.get("email")))
                .gender(String.valueOf(kakaoAccount.get("gender")))
                .ageRange(String.valueOf(kakaoAccount.get("age_range")))
                .profileImageUrl(String.valueOf(kakaoProfile.get("profile_image_url")))
                .nameAttributesKey(userNameAttributeName)
                .attributes(attributes)
                .build();
    }

    public static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");

        return OAuthAttributes.builder()
                .id(String.valueOf(response.get("id")))
                .name(String.valueOf(response.get("nickname")))
                .email(String.valueOf(response.get("email")))
                .profileImageUrl(String.valueOf(response.get("profile_image")))
                .ageRange((String) response.get("age"))
                .gender((String) response.get("gender"))
                .attributes(response)
                .nameAttributesKey(userNameAttributeName)
                .build();
    }

}