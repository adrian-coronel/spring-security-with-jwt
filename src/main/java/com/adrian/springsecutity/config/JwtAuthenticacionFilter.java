package com.adrian.springsecutity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;


@Component // Indicamos que es componente
@RequiredArgsConstructor // Creará un constructor con los atributos finales REQUERIDOS
public class JwtAuthenticacionFilter extends OncePerRequestFilter {
// "OnePerRequestFilter" asegura que el filtro se aplique solo una vez por solicitud HTTP,
// independientemente de cuántas veces se invoque, garantiza que no se repitan acciones innecesariamente.

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // Vamos a solicitar el header "Authorization", que será el que tendrá TOKEN
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Si no hay un TOKEN o el TOKEN no comienza por Bearer (comun en los headers de autorizacion)
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); // Siga con el siguiente filtro
            return;
        }
        jwt = authHeader.substring(7); // Obtenemos el token desde la posicion para excluir "Bearer "
        userEmail = jwtService.extractUsername(jwt);

        // Verificamos si el usuario AUN NO ESTA AUTENTICADO
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            //Obtenemos los detalles del usuario de la base de datos
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Si el token es valido
            if (jwtService.isTokenvalid(jwt, userDetails)){
                // Es necesario usar esta clase para actualizar el contexto de seguridad
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, //Detalles del usuario autenticado
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // Acutalizamos el token de autenticacion
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            filterChain.doFilter(request, response);;
        }
    }
}
