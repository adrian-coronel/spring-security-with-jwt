package com.adrian.springsecutity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // Clave generada en desde una plataforma: https://generate-random.org/encryption-key-generator
    private static final String SECRET_KEY = "JAKMqn64Zj2foktSNqMaZ/78Q5lCR9uUBsowbyt6FRT7BK1yJ8EFtJUiHPZWTLYwFc8Gzw/sSNYSP2B1KeHKxZOMPAswRuuTAXGCsVgA+NW5FwIaeRCt9GGrmnINUwyd1UE20pCOzUBg1b5qwVV1usBTPHi8h2gLhFBp7gMwQ/d1lZtvEu+zDc3FKm0GQMQp/Np5p16kiHf5/SjcTrX5vlB8M7yGS5gV1Eprsu6fWirDwlgFATlIcAEIc615C+ZGa8hGx+7a58hBxzcHjwDNWv5VRs+AlKuHfavEQzYSIfxD3Dbna1a1ruqi2N32NV8kGsEFJeWVJ09B7hTDfn2C/crT2s41ZGR8VHk7IavEH+Y=\n"; // Nivel Minimo para TOKENS 256-bits

    /**
     * Extraer el USERNAME del TOKEN
     * */
    public String extractUsername(String token) {
        // Se extrae el subject que generalmente contiene el username
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generar un token sin Claims
     * */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generar un token con Claims Extras
     * */
    public String generateToken(
            Map<String, Object> extraClaims, //Parámetro para incluir reclamos(claims) adicionales
            UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername()) // El token contendrá el EMAIL
                .setIssuedAt(new Date(System.currentTimeMillis())) // Fecha en que se generó el token, le pasamos los milisegundos actuales
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1440))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // Establecemos la FIRMA y el algoritmo de firma
                .compact(); // "compact" Generará y devuelve el TOKEN
    }

    public boolean isTokenvalid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }

    /**
     * Comprueba si la fecha de EXPIRACIÓN es anteorior a la actual es TRUE
     * */
    private boolean isTokenExpired(String token) {
        // "before" Prueba si esta fecha es anterior a la fecha especificada.
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extrae la fecha de EXPIRACION del TOKEN
     * */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Extrae un solo Claims del token
     * */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); //Permite extraer un claim específico del token según la función
        // proporcionada y devolverlo en el formato deseado (de tipo T).
    }

    /**
     * Extrae todos los claims del token
     * */
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey( getSignInKey() ) // PASAMOS LA FIRMA
                .build()
                .parseClaimsJws(token) // Obtenemos los claims(elementos de información q contiene el token)
                .getBody(); // Obtenemos el cuerpo
    }

    /**
     * Devuelve la CLAVE DE FIRMA
     * */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // Pasamos el formato de SECRET_KEY, de BASE64 a Bytes
        // hmacSha... crea una clave HMAC (Hash-based Message Authentication Code) a partir de los bytes
        return Keys.hmacShaKeyFor(keyBytes); //HMAC se utiliza para firmar y verificar tokens de seguridad.
    }
}
