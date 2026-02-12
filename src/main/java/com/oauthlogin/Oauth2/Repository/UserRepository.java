package com.oauthlogin.Oauth2.Repository;


import com.oauthlogin.Oauth2.Entity.UserDetailsEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserDetailsEntity,Long> {

    Optional<UserDetailsEntity> findByEmail(String Email);
}
