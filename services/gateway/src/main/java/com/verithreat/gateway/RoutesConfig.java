package com.verithreat.gateway;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.web.servlet.function.RequestPredicates.path;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Rutas del Gateway. Toda petición a /api/** necesita una clave de API válida en X-API-Key. El Gateway borra las
 * cabeceras de identidad que mande el cliente, pone la organización real de la clave en X-Organization y añade el
 * secreto compartido X-Gateway-Token, para que ioc-service sepa que la petición ha pasado por aquí.
 */
@Configuration
public class RoutesConfig {

    static final String API_KEY = "X-API-Key";
    static final String ORGANIZATION = "X-Organization";
    static final String GATEWAY_TOKEN = "X-Gateway-Token";

    @Bean
    RouterFunction<ServerResponse> iocServiceRoute(@Value("${verithreat.ioc-service-url}") String iocServiceUrl,
                                                   ApiKeyService keys,
                                                   @Value("${verithreat.gateway-token:}") String gatewayToken) {
        return route("ioc-service")
                .route(path("/api/**"), http())
                .before(uri(iocServiceUrl))
                .filter(authenticate(keys, gatewayToken))
                .build();
    }

    static HandlerFilterFunction<ServerResponse, ServerResponse> authenticate(ApiKeyService keys, String gatewayToken) {
        return (request, next) -> {
            Optional<String> org = keys.organizationFor(request.headers().firstHeader(API_KEY));
            if (org.isEmpty()) {
                ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED,
                        "missing or invalid API key (header " + API_KEY + ")");
                p.setTitle("Unauthorized");
                return ServerResponse.status(HttpStatus.UNAUTHORIZED).contentType(MediaType.APPLICATION_PROBLEM_JSON)
                        .body(p);
            }
            ServerRequest forwarded = ServerRequest.from(request).headers(h -> {
                h.remove(API_KEY);          // la clave no sale del Gateway
                h.remove(ORGANIZATION);     // nadie puede decir ser otra organización
                h.remove(GATEWAY_TOKEN);
                h.set(ORGANIZATION, org.get());
                if (!gatewayToken.isBlank()) {
                    h.set(GATEWAY_TOKEN, gatewayToken);
                }
            }).build();
            return next.handle(forwarded);
        };
    }
}
