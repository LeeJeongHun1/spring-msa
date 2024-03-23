package com.authserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Builder
public class JoinRequest {

    @Schema(description = "userId (email)", requiredMode = Schema.RequiredMode.REQUIRED)
    private String userId;
    @Schema(description = "password", requiredMode = Schema.RequiredMode.REQUIRED)
    private String password;
    @Schema(description = "name", requiredMode = Schema.RequiredMode.REQUIRED)
    private String name;

}
