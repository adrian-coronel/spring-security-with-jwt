package com.adrian.springsecutity.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Si intentamos acceder a esta ruta sin antes AUTENTICARNOS se nos mostrará un estado 403
 * 403: el servidor ha recibido y ha entendido la petición, pero rechaza enviar una respuesta.
 * */
@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello form secured endpoint");
    }

}
