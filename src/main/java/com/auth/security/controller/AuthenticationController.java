package com.auth.security.controller;

import com.auth.security.model.AuthenticationDetails;
import com.auth.security.model.AuthenticationToken;
import com.auth.security.service.AuthenticationService;
import com.auth.security.service.LoginService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/authentication/api")
@Tag(name = "Authentication")
public class AuthenticationController {
    private final LoginService loginService;
    private final AuthenticationService authenticationService;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationToken> authenticate(@RequestBody AuthenticationDetails details) {
        return ResponseEntity.ok(loginService.authenticate(details));
    }

    @GetMapping("/internal-url")
    public ResponseEntity<Void> internalUrl() {
        return ResponseEntity.ok().build();
    }

    @GetMapping("/generate-valid-token")
    public ResponseEntity<AuthenticationToken> generateToken() {
        String token = authenticationService.getToken();
        if (!StringUtils.hasText(token)) {
            return ResponseEntity.ok(null);
        }
        return ResponseEntity.ok(new AuthenticationToken(authenticationService.generateNewEncodedToken(token)));
    }
}
