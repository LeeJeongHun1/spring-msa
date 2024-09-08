package com.authserver.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import lombok.RequiredArgsConstructor;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.method.HandlerMethod;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import static java.util.stream.Collectors.groupingBy;

@OpenAPIDefinition(
        info = @Info(title = "인증 모듈 API",
                description = "<div>"
//                    + "<span>API URL : {baseUrl}/auth/{apiPath}</span><br><br>"
//                    + "<span>baseUrl (DEV): https://firstchart.whatailsyou.io</span><br>"
//                    + "<span>baseUrl (PROD): 미정</span><br><br>"
//                    + "<span>공통 ResponseBody</span>"
//                    + "<div><pre><code>"
//                    + "<span>{</span><br>"
//                    + "<span>  \"status\": 200, //API 응답코드 (Http statusCode와는 별개)</span><br>"
//                    + "<span>  \"data\"</span><span>: {}, //데이터</span><br>"
//                    + "<span>  \"message\": \"success\", //ResponseStatus에 대한 메세지</span><br>"
//                    + "<span>  \"timestamp\": \"2024-01-01 09:30:00\", //API 응답일시 (yyyy-MM-dd HH:mm:ss)</span><br>"
//                    + "<span>  \"trace\": \"\", //디버깅용 메세지</span><br>"
//                    + "<span>  \"path\": \"/api/v1/test\" //요청 API path</span><br>"
//                    + "<span>}</span>"
//                    + "</code></pre></div>"
//                    + "<span>공통 응답코드 및 메세지</span>"
//                    + "<div><pre><code>"
//                    + "<span>(http)statusCode: 200</span><br>"
//                    + "  (응답코드)status: 200, message: success</span><br>"
////                    + "<span>(http)statusCode: 400</span><br>"
//                    + "<span>(http)statusCode: 401</span><br>"
//                    + "  (응답코드)status: -1, message: 유효하지 않는 TOKEN 입니다. 로그인을 다시 시도하세요.</span><br>"
//                    + "  (응답코드)status: -2, message: 토큰을 찾을 수 없습니다.</span><br>"
//                    + "  (응답코드)status: -3, message: 이미 만료된 토큰입니다.</span><br>"
//                    + "  (응답코드)status: -4, message: 인증 헤더 정보가 존재하지 않습니다.</span><br>"
//                    + "  (응답코드)status: -7, message: refreshToken 정보가 쿠키에 존재하지않습니다.</span><br>"
//                    + "  (응답코드)status: -8, message: 쿠키에 존재하지 않습니다.</span><br>"
//                    + "<span>(http)statusCode: 403</span><br>"
//                    + "  (응답코드)status: -113, message: 접근권한이 없습니다.</span><br>"
//                    + "<span>(http)statusCode: 500</span><br>"
//                    + "  (응답코드)status: -999, message: 알수 없는 오류입니다.</span><br>"
//                    + "</code></pre></div>"
                    + "</div>",
                version = "v1"))
@RequiredArgsConstructor
@Configuration
public class SwaggerConfig {

    private final ApplicationContext applicationContext;

    @Bean
    ForwardedHeaderFilter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    @Bean
    public GroupedOpenApi chatOpenApi() {
        String[] paths = {"/api/v1/**"};

        return GroupedOpenApi.builder()
                .group("인증 모듈 API v1")
                .pathsToMatch(paths)
                .build();
    }

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .name("bearerAuth")
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                        )
                )
                .info(new io.swagger.v3.oas.models.info.Info().version("v2").title("인증 모듈 API").description("인증 모듈 API v1"))
                .addServersItem(new Server().url("/auth"))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }

//    @Bean
//    public OperationCustomizer customize() {
//        return (Operation operation, HandlerMethod handlerMethod) -> {
//            ErrorException errorException =
//                    handlerMethod.getMethodAnnotation(ErrorException.class);
//            List<String> tags = getTags(handlerMethod);
//
//            // 태그 중복 설정시 제일 구체적인 값만 태그로 설정
//            if (!tags.isEmpty()) {
//                operation.setTags(Collections.singletonList(tags.get(0)));
//            }
//            // ErrorException 어노테이션 단 메소드 적용
//            if (errorException != null) {
//                generateExceptionResponse(operation, errorException.value());
//            }
//            return operation;
//        };
//    }
//
//    // type -> SwaggerException을 상속받은 Class
//    private void generateExceptionResponse(Operation operation, Class<?> type) {
//        ApiResponses responses = operation.getResponses();
//
//        Object bean = applicationContext.getBean(type);
//        List<ResponseCode> responseCodes;
//        try {
//            Method method = bean.getClass().getMethod(operation.getOperationId());
//            Object returnValue = method.invoke(bean);
//            responseCodes = (List<ResponseCode>) returnValue;
//        } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
//            throw new GlobalException(ResponseCode.NOT_PARSING_SWAGGER);
//        }
//
//        Map<Integer, List<SwaggerHolder>> statusWithSwaggerHolders = responseCodes.stream()
//                .map(responseCode -> SwaggerHolder.builder()
//                        .holder(getSwaggerExample(responseCode))
//                        .code(responseCode.getHttpStatus())
//                        .name(responseCode.getMessage())
//                        .build())
//                .collect(groupingBy(SwaggerHolder::getCode));
//
//        // -------------------------- 콘텐츠 세팅 코드별로 진행
//        addExamplesToResponses(responses, statusWithSwaggerHolders);
//    }
//
//    private Example getSwaggerExample(ResponseCode responseCode) {
//        Example example = new Example();
//        GlobalException globalException = new GlobalException(responseCode);
//        example.description(responseCode.getMessage());
//        example.setValue(GlobalBody.errorWithMessageData(globalException.getData(), globalException));
//        return example;
//    }
//
//    private void addExamplesToResponses(ApiResponses responses, Map<Integer, List<SwaggerHolder>> statusWithExampleHolders) {
//        statusWithExampleHolders.forEach(
//                (status, v) -> {
//                    Content content = new Content();
//                    MediaType mediaType = new MediaType();
//                    ApiResponse apiResponse = new ApiResponse();
//                    v.forEach(
//                            swaggerHolder -> {
//                                mediaType.addExamples(
//                                        swaggerHolder.getName(), swaggerHolder.getHolder());
//                            });
//                    content.addMediaType("application/json", mediaType);
//                    apiResponse.setContent(content);
//                    responses.addApiResponse(status.toString(), apiResponse);
//                });
//    }

    private static List<String> getTags(HandlerMethod handlerMethod) {
        List<String> tags = new ArrayList<>();

        Tag[] methodTags = handlerMethod.getMethod().getAnnotationsByType(Tag.class);
        List<String> methodTagStrings =
                Arrays.stream(methodTags).map(Tag::name).toList();

        Tag[] classTags = handlerMethod.getClass().getAnnotationsByType(Tag.class);
        List<String> classTagStrings =
                Arrays.stream(classTags).map(Tag::name).toList();
        tags.addAll(methodTagStrings);
        tags.addAll(classTagStrings);
        return tags;
    }
}
