package com.oauthlogin.Oauth2.Security;

import com.oauthlogin.Oauth2.Entity.UserDetailsEntity;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;


public class UserPrincipal implements UserDetails {
    private UserDetailsEntity userDetailsEntity;

    public UserPrincipal(UserDetailsEntity userDetailsEntity) {
        this.userDetailsEntity = userDetailsEntity;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_"+userDetailsEntity.getRole()));
    }

    @Override
    public @Nullable String getPassword() {
        return userDetailsEntity.getPassword();
    }

    @Override
    public String getUsername() {
        return userDetailsEntity.getName();
    }
}
