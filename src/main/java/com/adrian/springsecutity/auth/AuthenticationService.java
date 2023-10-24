package com.adrian.springsecutity.auth;

import com.adrian.springsecutity.config.JwtService;
import com.adrian.springsecutity.user.Role;
import com.adrian.springsecutity.user.User;
import com.adrian.springsecutity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository userRepository;
    //Configuramos que se use "BCryptPasswordEncoder" como codificardor de Passwords
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    /**
     * Metodo para registrar un usuario
     * @return token
     * */
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                // Encriptamos las contraseña antes de guardarla en BD
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER) // Usamos nuestro rol estatico
                .build();

        //Guardamos el usuario y generamos un token con sus detalles
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken) // Retornamos el TOKEN contenido por "AuthenticationResponse"
                .build();
    }

    /**
     * Metodo para autenticar un usuario
     * @return token
     * */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // Usamos el Administrador de Autentificacion para AUTENTICAR AL USUARIO
        authenticationManager.authenticate(
                //El administrador realiza tod0 el trabajo
                // En caso exista un error se arrojará un excepción
                new UsernamePasswordAuthenticationToken(
                  request.getEmail(),
                  request.getPassword()
                )
        );

        // Buscamos al usuario y generamos un token con sus detalles
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken) // Retornamos el TOKEN contenido por "AuthenticationResponse"
                .build();
    }
}
