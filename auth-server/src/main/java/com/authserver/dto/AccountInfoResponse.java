package com.authserver.dto;

import com.authserver.entity.QAccount;
import com.authserver.entity.QSocial;
import com.querydsl.core.annotations.QueryProjection;
import com.querydsl.core.types.ConstructorExpression;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
@NotNull
public class AccountInfoResponse {

    @Parameter(description = "userId (email)")
    private String userId;
    @Parameter(description = "name")
    private String name;

    @Parameter(description = "social")
    private String social;


    @QueryProjection
    public AccountInfoResponse(String userId, String name, String social) {
        this.userId = userId;
        this.name = name;
        this.social = social;
    }

    public static ConstructorExpression<AccountInfoResponse> create(QAccount account, QSocial social) {
        return new QAccountInfoResponse(
                account.userId,
                account.name,
                social.socialType.stringValue()
        );
    }
}
