package com.oauthlogin.Oauth2.Controller;

import com.oauthlogin.Oauth2.DTO.UserDto;
import com.oauthlogin.Oauth2.Security.JwtUtil;
import com.oauthlogin.Oauth2.Security.SecurityConfiguration;
import com.oauthlogin.Oauth2.Services.MyUserServices;
import org.apache.catalina.User;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/auth")
public class UserController {

    private MyUserServices myUserServices;
    private AuthenticationManager authenticationManager;
    private JwtUtil jwtUtil;

    public UserController(MyUserServices myUserServices, AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.myUserServices = myUserServices;
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }
    @PostMapping("/signup")
    public ResponseEntity<String>createUser(@RequestBody UserDto userDto){
        return myUserServices.CreateUser(userDto);
    }
    @PostMapping("/login")
    public ResponseEntity<String>loginUser(@RequestBody UserDto userDto){
        Authentication authentication=authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userDto.getEmail(),userDto.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        List<String>roles=authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
        String token=jwtUtil.generateToken(userDto.getEmail(),roles);
        ResponseCookie cookie = ResponseCookie.from("token", token)
                .httpOnly(false)           // JavaScript cannot read the cookie
                .secure(false)            // true in production HTTPS
                .path("/")
                .maxAge(7 * 24 * 60 * 60) // 7 days
                .sameSite("Strict")       // mitigate CSRF
                .build();
        return ResponseEntity
                .ok()
                .header(HttpHeaders.SET_COOKIE,cookie.toString())
                .body(token);
    }


}
