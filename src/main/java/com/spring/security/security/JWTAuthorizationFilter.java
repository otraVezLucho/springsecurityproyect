package com.spring.security.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.spring.security.services.IJWTUtilityService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Collections;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Autowired
    IJWTUtilityService jwtUtilityService;

    public JWTAuthorizationFilter(IJWTUtilityService jwtUtilityService) {
        this.jwtUtilityService = jwtUtilityService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        //Obtener el JWT a travez del header authorization
        String header = request.getHeader("Authorization"); // El getHeader() tiene que ser la key y el value es el JWT

        if(header==null||
        !header.startsWith("Bearer")){
            filterChain.doFilter(request, response);
            return;
        }
        //Extraer el bearer del token
        String token = header.substring(7); // el 7 hace referencia a los primeros 7 caracteres

        try{
            JWTClaimsSet claims = jwtUtilityService.parceJWT(token); // parceJWT() va a pedir añadir las clausulas catch

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(claims.getSubject(),null, Collections.emptyList());

            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        filterChain.doFilter(request,response);
    }
}
