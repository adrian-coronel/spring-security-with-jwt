package com.adrian.springsecutity.config;

import com.adrian.springsecutity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Esta clase conteendra todas las configuraciones de nuestra aplicacion,
 * como por ejemplo contenedores
 */

// Spring tomará esta clase e intentará implementar e injectar todos los contenedores
@Configuration
@RequiredArgsConstructor // En caso de que queramos inyectar algo
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean //Marca un método como un productor de un bean gestionado por Spring.
    public UserDetailsService userDetailsService() {
        // Usamos lambda para definir la implementación del UserDetailsService.
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found."));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // Indicamos a SpringSecurity que use mi UserDetailsService personalizado
        authProvider.setUserDetailsService(userDetailsService());
        // Pasamos nuestro encriptador de contraseñas
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCryptPasswordEncoder será el que encriptará la contraseña
        return new BCryptPasswordEncoder();
    }

    /**
     *  El AuthenticationManager es un componente crucial en Spring Security que se encarga
     *  de la autenticación de los usuarios. Al obtenerlo de la configuración, se asegura
     *  que esté configurado y listo para su uso.
     * */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)
            throws Exception {
        // Usaremos el Administrador de Autentificacion de SpringSecurity
        return config.getAuthenticationManager();
    }
}
