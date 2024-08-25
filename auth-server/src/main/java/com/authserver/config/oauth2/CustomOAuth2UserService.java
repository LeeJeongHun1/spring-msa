package com.authserver.config.oauth2;

import com.authserver.entity.Account;
import com.authserver.entity.Social;
import com.authserver.enums.SocialType;
import com.authserver.repository.AccountRepository;
import com.authserver.repository.SocialRepository;
import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

@Transactional
@RequiredArgsConstructor
@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final AccountRepository accountRepository;
    private final SocialRepository socialRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> service = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = service.loadUser(userRequest);
        Map<String, Object> originAttributes = oAuth2User.getAttributes();

        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuthAttributes attributes = OAuthAttributes.of(registrationId, originAttributes);

        Optional<Account> account = accountRepository.findByUserId(attributes.getEmail());
        if (account.isEmpty()) { // 가입?

            Account savedAccount = Account.builder()
                    .userId(attributes.getEmail())
                    .name(attributes.getName())
                    .build();
            accountRepository.save(savedAccount);
            Social social = Social.builder()
                    .socialId(attributes.getId())
                    .account(savedAccount)
                    .accessToken(userRequest.getAccessToken().getTokenValue())
                    .socialType(SocialType.of(registrationId))
                    .socialEmail(attributes.getEmail())
                    .connectDate(LocalDateTime.now())
                    .build();
            socialRepository.save(social);
        }

        return new OAuth2CustomUser(registrationId, attributes, null);
    }
}
