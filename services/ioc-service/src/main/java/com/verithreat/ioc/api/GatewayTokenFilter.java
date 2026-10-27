package com.verithreat.ioc.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Solo acepta en /api/** las peticiones que traen el secreto compartido del Gateway (X-Gateway-Token). Así nadie puede
 * saltarse el Gateway y fijar X-Organization a su antojo. Sin GATEWAY_TOKEN configurado no se exige (desarrollo) y se
 * avisa al arrancar.
 */
@Component
public class GatewayTokenFilter extends OncePerRequestFilter {

    static final String HEADER = "X-Gateway-Token";
    private static final Logger log = LoggerFactory.getLogger(GatewayTokenFilter.class);

    private final byte[] token;

    public GatewayTokenFilter(@Value("${verithreat.gateway-token:}") String token) {
        this.token = token.getBytes(StandardCharsets.UTF_8);
        if (token.isBlank()) {
            log.warn("GATEWAY_TOKEN is not set: /api/** accepts requests that did not go through the gateway "
                    + "(development only)");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return token.length == 0 || !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String sent = request.getHeader(HEADER);
        // Comparación en tiempo constante: no revela por tiempos cuántos caracteres coinciden
        if (sent != null && MessageDigest.isEqual(token, sent.getBytes(StandardCharsets.UTF_8))) {
            chain.doFilter(request, response);
            return;
        }
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write("{\"title\":\"Unauthorized\",\"status\":401,"
                + "\"detail\":\"requests must go through the VeriThreat gateway\"}");
    }
}
