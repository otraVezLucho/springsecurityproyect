package com.spring.security.services.imp;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.spring.security.services.IJWTUtilityService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;

//Esta clase se va a encargar de crear el JWT y la validacion o parseo del JWT
@Service
public class JWTUtilityServiceImp implements IJWTUtilityService {


    @Value("classpath:jwtKeys/private_key.pem") //Al value se le agrega la ruta de la llave publica y de la llave privada que es la carpeta contenedora en el proyecto
    private Resource privateKeyResourse;

    @Value("classpath:jwtKeys/public_key.pem")
    private Resource publicKeyResource;

    //Metodos publicos para generar el JWT y el otro para validar que el JWT que se pasa es correcto
    @Override
    public  String generateJWT(Long userId) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {
        PrivateKey privateKey = loadPrivateKey(privateKeyResourse); // Se Agrega la excepcion generada por loadPrivateKey()

        JWSSigner signer = new RSASSASigner(privateKey);

            Date now = new Date();
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(userId.toString())
                    .issueTime(now)
                    .expirationTime(new Date(now.getTime() + 14400000))
                    .build();
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256),claimsSet);
            signedJWT.sign(signer); // Se Agrega la excepcion generada por sign()

        return signedJWT.serialize();

    }

    @Override
    public JWTClaimsSet parceJWT (String jwt) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, ParseException, JOSEException { // el parametro es el token que pase el cliente o quien se quiera autenticar en la aplicacion
        PublicKey publicKey = loadPublicKey(publicKeyResource); // Se Agrega la excepcion generada por  loadPublicKey()

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) publicKey);
        if (signedJWT.verify(verifier)){
            throw new JOSEException("Invalid signature");
        }
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        if(claimsSet.getExpirationTime().before(new Date())){
            throw new JOSEException("Expired Token");
        }

        return claimsSet;
    }


    // SE CREAN LOS METODOS PRIVADOS QUE PERMITAN LEER LA LLAVE PUBLICA Y LA PRIVADA YA GENERADAS

    private PrivateKey loadPrivateKey(Resource resource) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException { //El Resourse importado debe corresponder al paquete core.io

        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----","")
                .replace("-----END PRIVATE KEY-----","")
                .replaceAll("\\s","");//Esta linea lo que hace es que cuando coincide en un espacio en blanco lo va a quitar

        byte[] decodeKey = Base64.getDecoder().decode(privateKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Se Agrega la excepcion generada por  .getInstance()

        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodeKey)); // Se Agrega la excepcion generada por  .generatePrivate()
    }

    private PublicKey loadPublicKey(Resource resource) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(resource.getURI()));
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","")
                .replaceAll("\\s","");//Esta linea lo que hace es que cuando coincide en un espacio en blanco lo va a quitar

        byte[] decodeKey = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Se Agrega la excepcion generada por  .getInstance()

        return keyFactory.generatePublic(new X509EncodedKeySpec(decodeKey)); // Se Agrega la excepcion generada por  .generatePublic()

    }
}
