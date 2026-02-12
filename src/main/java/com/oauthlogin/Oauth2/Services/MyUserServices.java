package com.oauthlogin.Oauth2.Services;

import com.oauthlogin.Oauth2.DTO.UserDto;
import com.oauthlogin.Oauth2.Entity.UserDetailsEntity;
import com.oauthlogin.Oauth2.Mapper.UserMapper;
import com.oauthlogin.Oauth2.Repository.UserRepository;
import com.oauthlogin.Oauth2.Security.UserPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MyUserServices implements UserDetailsService {
    private UserRepository userRepository;
    private UserMapper userMapper;

    public MyUserServices(UserRepository userRepository, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.userMapper = userMapper;
    }



    public ResponseEntity<String>CreateUser(UserDto userDto){

        if(userRepository.findByEmail(userDto.getEmail()).isPresent()){
            return new ResponseEntity<>("Email Already Exist ", HttpStatus.CONFLICT);
        }

        userRepository.save(userMapper.convertUserDTOtoEntityForSignup(userDto));
        return ResponseEntity.ok("Signup Sucessfull");
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       Optional< UserDetailsEntity> userDetailsEntity=userRepository.findByEmail(username);
       if(userDetailsEntity.isEmpty()){
           throw new UsernameNotFoundException("User With Email "+username+"do not exist ");
       }
        return new UserPrincipal(userDetailsEntity.get());
    }


}
