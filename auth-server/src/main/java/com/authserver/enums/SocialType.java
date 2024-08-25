package com.authserver.enums;

import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import lombok.Getter;

import java.util.Arrays;

@Getter
public enum SocialType {
    GOOGLE("GOOGLE"),
    NAVER("NAVER"),
    KAKAO("KAKAO");

    private final String registrationId;

    SocialType(String registrationId) {
        this.registrationId = registrationId;
    }

    public static SocialType of(String registrationId) {
        return Arrays.stream(values()).filter(socialType -> socialType.getRegistrationId().equalsIgnoreCase(registrationId))
                .findFirst()
                .orElseThrow(() -> new GlobalException(ResponseCode.NOT_SUPPORTED_SOCIAL));
    }
}
