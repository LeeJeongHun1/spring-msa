package com.authserver.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
@NotNull
public class LoginRequest {

    @Schema(description = "userId (email)", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank @Email
    private String userId;
    @Schema(description = "password", requiredMode = Schema.RequiredMode.REQUIRED)
    @NotBlank
    private String password;
}
