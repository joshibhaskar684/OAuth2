package com.oauthlogin.Oauth2.Mapper;

import com.oauthlogin.Oauth2.DTO.UserDto;
import com.oauthlogin.Oauth2.Entity.UserDetailsEntity;
import com.oauthlogin.Oauth2.Repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserMapper {
    private UserRepository userRepository;

    public UserMapper(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public UserDetailsEntity convertUserDTOtoEntityForSignup(UserDto userDto){

      Optional<UserDetailsEntity> userDetailsEntity=  userRepository.findByEmail(userDto.getEmail());
      if(userDetailsEntity.isPresent()){
          return userDetailsEntity.get();
      }

        if (userRepository.findAll().isEmpty()){
            UserDetailsEntity user= new UserDetailsEntity();
            user.setEmail(userDto.getEmail());
            user.setRole("ADMIN");
            user.setName(userDto.getName());
            user.setPassword(new BCryptPasswordEncoder(12).encode(userDto.getPassword()));
            user.setMobile(userDto.getMobile());
            return user;
        }
      UserDetailsEntity user= new UserDetailsEntity();
      user.setEmail(userDto.getEmail());
      if(userDto.getRole()=="ADMIN"){
          user.setRole("USER");
      }
        user.setRole(userDto.getRole());
      user.setName(userDto.getName());
      user.setPassword(new BCryptPasswordEncoder(12).encode(userDto.getPassword()));
      user.setMobile(userDto.getMobile());
      return user;
    }


    public UserDetailsEntity convertUserDTOtoEntity(UserDto userDto){
       if(!userDto.getEmail().isEmpty()){
        Optional<UserDetailsEntity> userDetailsEntity=  userRepository.findByEmail(userDto.getEmail());
        if(userDetailsEntity.isPresent()){
            return userDetailsEntity.get();
        }
       }
        if(!userDto.getId().describeConstable().isEmpty()) {
            Optional<UserDetailsEntity> userDetailsEntity1 = userRepository.findById(userDto.getId());
            if (userDetailsEntity1.isPresent()) {
                return userDetailsEntity1.get();
            }
        }
        UserDetailsEntity user= new UserDetailsEntity();
        user.setId(userDto.getId());
        user.setEmail(userDto.getEmail());
        user.setRole(userDto.getRole());
        user.setName(userDto.getName());
        user.setPassword(userDto.getPassword());
        user.setMobile(userDto.getMobile());
        return user;
    }




    public UserDto convertUserEntityToDTO(UserDetailsEntity user){

        UserDto userDto= new UserDto();
        userDto.setId(user.getId());
        userDto.setEmail(user.getEmail());
        userDto.setRole(user.getRole());
        userDto.setName(user.getName());
        userDto.setPassword("");
        userDto.setMobile(user.getMobile());
        return userDto;
    }

}
