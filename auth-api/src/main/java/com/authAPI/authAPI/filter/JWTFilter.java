package com.authAPI.authAPI.filter;

import com.authAPI.authAPI.services.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Component
public class JWTFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            // Get the Authorization header
            String header = request.getHeader("Authorization");
            System.out.println("Authorization header: " + header);

            // Check if the Authorization header is present and starts with "Bearer "
            if (header != null && header.startsWith("Bearer ")) {
                String token = header.substring(7); // Extract token
                System.out.println("Processing token: " + token);

                // Validate the token
                if (jwtService.validateToken(token, jwtService.getUsername(token))) {
                    // Set authentication in the SecurityContext

                    // Get username from token
                    String username = jwtService.getUsername(token);
                    System.out.println("Username from token: " + username);

                    String role = jwtService.getRole(token);
                    System.out.println("Role from token: "+ role);

                    // Authorities list with the single role (if it exists
                    List<SimpleGrantedAuthority> authorities = role != null ?
                            List.of(new SimpleGrantedAuthority("ROLE_" + role)) :
                            List.of();
                    System.out.println("Authorities: " + authorities);

                    // Here we create a UsernamePasswordAuthenticationToken
                    UsernamePasswordAuthenticationToken authenticationToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
        } catch (Exception e) {
            System.out.println("JWTFilter error: " + e.getMessage());
            e.printStackTrace();
        }

        chain.doFilter(request, response);
    }
}