package com.spring.security.services.imp;

import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.persistence.repositories.UserRepository;
import com.spring.security.services.IAuthService;
import com.spring.security.services.IJWTUtilityService;
import com.spring.security.services.models.dtos.LoginDTO;
import com.spring.security.services.models.dtos.ResponseDTO;
import com.spring.security.services.models.validations.UserValidations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class AuthServiceImp implements IAuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private IJWTUtilityService jwtUtilityService;

    @Autowired
    private UserValidations userValidations;

        //Ejemplo usando un HashMap
    @Override
    public HashMap<String,String> login(LoginDTO login) throws Exception {
        try{
            HashMap<String,String> jwt = new HashMap<>();
            Optional<UserEntity> user = userRepository.findByEmail(login.getEmail());   //Buscar al usuario por email y usa el metodo creado en la interfaz UserRepository
                if (user.isEmpty()){
                    jwt.put("error","user not registered");
                    return jwt;
                }
                //Verificar la contraseña
            if (verifyPassword(login.getPassword(), user.get().getPassword())){
                    jwt.put("jwt", jwtUtilityService.generateJWT(user.get().getId())); // Metodo generateJWT() solicita el userId quie viene de la interfaz IJWTUtilityService
            }else {
                jwt.put("error","Authentication failed");
            }
            return jwt;

        }catch (Exception e){
            throw new Exception(e.toString());
        }

    }

        //Ejemplo usando solo 1 DTO sin usar un hashMap
    public ResponseDTO register(UserEntity user) throws Exception{
        try{
            ResponseDTO response = userValidations.validate(user);


            if(response.getNumOfErrors() > 0){
                return response;
            }

            List<UserEntity> getAllUsers = userRepository.findAll(); //El metodo userRepository es nativo, no existe en la interfaz UserRepository

            for (UserEntity repetFields : getAllUsers){
                if (repetFields != null){
                    response.setNumOfErrors(1);
                    response.setMessage("User already exist!");
                    return response;
                }
            }

            //Encriptar la contraseña, y se va a encriptar antes de guardarla en la base de datos
            BCryptPasswordEncoder encoder =  new BCryptPasswordEncoder(12);
            user.setPassword(encoder.encode(user.getPassword()));
            userRepository.save(user);
            response.setMessage("User created succesfully!");
            return response;

        }catch (Exception e){
            throw new Exception(e.toString());
        }
    }

    private boolean verifyPassword(String enteredPassword,String storedPassword ){
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        return encoder.matches(enteredPassword, storedPassword);
    }
}
