package com.oauthlogin.Oauth2.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

@Component
public class JwtUtil {
    @Value("${jwt.secretkey}")
    private String jwtSecretKey;

public String generateToken(String username, List<String> roles ){
    return Jwts.builder()
            .setSubject(username)
            .claim("roles",roles)
            .setExpiration(new Date(System.currentTimeMillis()+1000*60*60*24*7))
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .signWith(getSigningKey(), SignatureAlgorithm.HS256)
            .compact();
}

    public Key getSigningKey(){
        byte keybytes[]= Decoders.BASE64.decode(jwtSecretKey);
        return Keys.hmacShaKeyFor(keybytes);
    }

    public Boolean isTokenVaild(String token,String username){
        return extractUsername(token).equals(username) && !isTokenExpird(token);

    }
    public String extractUsername(String token){
        return extractAllClaims(token, Claims::getSubject);
    }
    public Date extractExpiration (String token){
        return extractAllClaims(token,Claims::getExpiration);
    }
    public Boolean isTokenExpird(String token){
        return extractExpiration(token).before(new Date());
    }
    public List<String>extractRoles(String token){
        return extractAllClaims(token,claims -> claims.get("roles",List.class));
    }


    public <T>T extractAllClaims(String token, Function<Claims,T> claimsTFunction){
        final Claims claims=Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsTFunction.apply(claims);
    }



}
