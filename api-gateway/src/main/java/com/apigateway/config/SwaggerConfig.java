package com.apigateway.config;

import org.springdoc.core.properties.SwaggerUiConfigParameters;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.cloud.gateway.route.RouteDefinitionLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;

import java.util.Arrays;
import java.util.List;

@Profile({"local", "devel"})
@Configuration
@Primary
public class SwaggerConfig {

    @Autowired
    RouteDefinitionLocator locator;

    @Bean
    public SwaggerUiConfigParameters swaggerUiConfigParameters() {
        SwaggerUiConfigProperties properties = new SwaggerUiConfigProperties();
        properties.setOperationsSorter("method");
        properties.setTagsSorter("alpha");
        return new SwaggerUiConfigParameters(properties);
    }

    @Bean
    public CommandLineRunner openApiGroups(RouteDefinitionLocator locator) {
        locator.getRouteDefinitions().collectList().block()
                .stream()
                .map(RouteDefinition::getId)
                .filter(id -> id.matches(".*-service"))
                .forEach(System.out::println);

        return args -> locator.getRouteDefinitions().collectList().block()
                .stream()
                .map(RouteDefinition::getId)
                .filter(id -> id.matches(".*-service"))
                .map(id -> id.replace("-service", ""))
                .forEach(swaggerUiConfigParameters()::addGroup);
    }
}
