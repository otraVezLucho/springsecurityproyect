package com.spring.security.services.imp;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImp implements IUserService {

    @Autowired
    UserRepository userRepository;


    @Override
    public List<UserEntity> findAllUsers() {
        return userRepository.findAll();
    }
}
