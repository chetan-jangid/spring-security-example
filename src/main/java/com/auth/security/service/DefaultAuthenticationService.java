package com.auth.security.service;

import com.auth.security.model.UserAccount;
import com.auth.security.model.UserDetailsResponse;
import com.auth.security.repository.UserRepository;
import com.auth.security.repository.exception.AuthException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class DefaultAuthenticationService implements AuthenticationService {
    private static final String HEADER_AUTH_KEY = "Authorization";
    /**
     * Token secret key should be received via external file or via externalization.
     * We are hardcoding here for learning purposes.
     */
    private static final String TOKEN_SECRET_KEY = "$A@#[4:>/@%?:5;(=]];.8/L$Z)=9[]M.#,0$>&?Q#=<?:]";
    private final UserRepository userRepository;

    @Override
    public UserDetailsResponse getUserDetails() {
        String username = getUsername();
        UserAccount userAccount = userRepository.findByUsername(username);
        return new UserDetailsResponse(userAccount.getUsername(), userAccount.getPassword(), userAccount.getRoles());
    }

    @Override
    public String getUsername() throws AuthException {
        return getClaims(getToken()).getSubject();
    }

    @Override
    public String generateNewEncodedToken(String token) throws AuthException {
        String username = getClaims(token).getSubject();
        return generateToken(username);
    }

    @Override
    public String generateToken(String subject) throws AuthException {
        Objects.requireNonNull(subject, () -> {
            throw new BadCredentialsException("Invalid username! Cannot create authentication.");
        });
        return buildToken(subject);
    }

    @Override
    public String getToken() {
        HttpServletRequest request = ((ServletRequestAttributes) Objects
                .requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
        final String token = request.getHeader(HEADER_AUTH_KEY);
        if (Objects.nonNull(token) && StringUtils.hasText(token)) {
            return token;
        }
        return null;
    }

    private String buildToken(String username) {
        Instant instant = Instant.now();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(instant))
                .setExpiration(Date.from(instant.plus(30L, ChronoUnit.MINUTES)))
                .signWith(new SecretKeySpec(Base64.getEncoder()
                        .encode(TOKEN_SECRET_KEY.getBytes(StandardCharsets.UTF_8)),
                        SignatureAlgorithm.HS256.getJcaName()), SignatureAlgorithm.HS256)
                .compact();
    }

    private Claims getClaims(String token) throws AuthException {
        return Jwts.parserBuilder()
                .setSigningKey(new SecretKeySpec(Base64.getEncoder()
                        .encode(TOKEN_SECRET_KEY.getBytes(StandardCharsets.UTF_8)),
                        SignatureAlgorithm.HS256.getJcaName()))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
