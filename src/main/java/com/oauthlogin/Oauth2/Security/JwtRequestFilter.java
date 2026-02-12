package com.oauthlogin.Oauth2.Security;

import com.oauthlogin.Oauth2.Services.MyUserServices;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
    private JwtUtil jwtUtil;
    private MyUserServices myUserServices;


    public JwtRequestFilter(JwtUtil jwtUtil, MyUserServices myUserServices) {

        this.jwtUtil = jwtUtil;
        this.myUserServices = myUserServices;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String AuthHeader=request.getHeader("Authorization");
        String username =null;
        String token=null;

        if(AuthHeader!=null&&AuthHeader.startsWith("Bearer ")){
            token=AuthHeader.substring(7);
            username=jwtUtil.extractUsername(token);


        }

        if(username!=null&& SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails=myUserServices.loadUserByUsername(username);
            List<String >roles=jwtUtil.extractRoles(token);
            List<SimpleGrantedAuthority>  authorities=roles
                    .stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
            if(jwtUtil.isTokenVaild(token,userDetails.getUsername())){
                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=new UsernamePasswordAuthenticationToken(userDetails,null,authorities);
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            }
        }
        filterChain.doFilter(request,response);

    }
}
