package com.spring.security.persistence.repositories;

import com.spring.security.persistence.entities.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    //Realizar busqueda de usuario por email

    //se puede hacer con JPA repository porque hay un metodo que lo permite
    //O se puede hacer por medio de una query nativa


    //se usa :email porque hay que hacer referencia al primer parametro del metodo del metodo abstracto que se va a crear y el segundo argumento es un native query
    @Query(value = "SELECT * FROM user WHERE email = :email", nativeQuery = true) //Esto siempre debe ir acompañado de un Optional pórque puede o no devolver algo
    Optional<UserEntity> findByEmail(String email);


}
