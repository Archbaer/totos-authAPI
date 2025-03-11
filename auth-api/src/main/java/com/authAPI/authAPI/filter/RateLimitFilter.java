package com.authAPI.authAPI.filter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitFilter implements Filter {

    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    private Bucket createNewBucket() {
        return Bucket4j.builder()
                .addLimit(Bandwidth.classic(30, Refill.greedy(30, Duration.ofMinutes(1))))
                .build();
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String ip = httpServletRequest.getRemoteAddr();

        System.out.println("IP: " + ip);

        Bucket bucket = buckets.computeIfAbsent(ip, k -> createNewBucket());

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            response.getWriter().write("Too Many Requests");
            ((jakarta.servlet.http.HttpServletResponse) response).setStatus(429);
        }
    }
}
