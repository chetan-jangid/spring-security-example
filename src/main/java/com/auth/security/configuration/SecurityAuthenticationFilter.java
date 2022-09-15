package com.auth.security.configuration;

import com.auth.security.repository.exception.AuthException;
import com.auth.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@RequiredArgsConstructor
@Slf4j
public class SecurityAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationService authenticationService;
    private final SecurityUserDetailsService securityUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        log.info("[Request]: {}", request.getRequestURI());
        if (SecurityContextHolder.getContext().getAuthentication() == null &&
                !request.getRequestURI().contains("account/authenticate")) {
            final String token = authenticationService.getToken();
            if (StringUtils.hasLength(token)) {
                log.info("Processing token: {}", token);
                String username = authenticationService.getUsername();
                authenticate(request, username);
            }
        }

        chain.doFilter(request, response);
    }

    private void authenticate(HttpServletRequest request, String username) throws AuthException {
        UserDetails userDetails = securityUserDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken = new
                UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
}
