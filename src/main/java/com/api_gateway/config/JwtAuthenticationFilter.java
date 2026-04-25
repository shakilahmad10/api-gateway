package com.api_gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             org.springframework.cloud.gateway.filter.GatewayFilterChain chain) {

        String path = exchange.getRequest().getURI().getPath();
        System.out.println("PATH: " + path);

        // ✅ Allow auth endpoints
        if (path.startsWith("/api/auth")) {
            return chain.filter(exchange);
        }

        // ✅ Get Authorization header
        String authHeader = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        System.out.println("AUTH HEADER: " + authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("❌ Missing or invalid Authorization header");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);
        System.out.println("TOKEN: " + token);

        try {
            boolean isValid = jwtUtil.validateToken(token);

            if (!isValid) {
                throw new RuntimeException("Invalid token");
            }

            String email = jwtUtil.extractEmail(token);
            String role = jwtUtil.extractRole(token);

            ServerHttpRequest modifiedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
                @Override
                public HttpHeaders getHeaders() {
                    HttpHeaders headers = new HttpHeaders();
                    headers.addAll(super.getHeaders());
                    headers.set("X-User-Email", email);
                    headers.set("X-User-Role", role);
                    return HttpHeaders.readOnlyHttpHeaders(headers);
                }
            };

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            System.out.println("❌ REAL ERROR:");
            e.printStackTrace();

            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }
}