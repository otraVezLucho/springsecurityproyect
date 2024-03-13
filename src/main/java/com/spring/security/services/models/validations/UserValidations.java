package com.spring.security.services.models.validations;


import com.spring.security.persistence.entities.UserEntity;
import com.spring.security.services.models.dtos.ResponseDTO;

//IMPORTANTE: Esta validacion se puede hacer directamente en la entidad UserEntity pero haciendolo de esta manera se puede controlar la respuesta
public class UserValidations {

    public ResponseDTO validate(UserEntity user){
        ResponseDTO response = new ResponseDTO();

        response.setNumOfErrors(0);
            if (user.getFirstName() == null ||
                    user.getFirstName().length() < 3 ||
                    user.getFirstName().length() > 15
            ){
                response.setNumOfErrors(response.getNumOfErrors() + 1);
                response.setMessage("El campo first Name no puede ser nulo y debe tener entre 3 y 15 caracteres");
            }

            if(user.getLastName() == null ||
                    user.getLastName().length() <3 ||
                    user.getLastName().length()>30
            ){
                response.setNumOfErrors(response.getNumOfErrors()+ 1);
                response.setMessage("El campo last Name no puede ser nulo y debe tener entre 3 y 30 caracteres");
            }
            if (user.getEmail()== null ||
                !user.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$") //expresión regular (regex) que se utiliza para validar si una cadena de texto representa una dirección de correo electrónico válida.
            ){
                response.setNumOfErrors(response.getNumOfErrors()+ 1);
                response.setMessage("El campo email no es valido");
            }
            if(user.getPassword()== null||
                !user.getPassword().matches("^(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,16}$")){
                response.setNumOfErrors(response.getNumOfErrors()+ 1);
                response.setMessage("Contraseña debe tener entre 8 y 16 caracteres, al menos un número, una minuscula y una mayuscula");
            }

        return response;
    }
}
