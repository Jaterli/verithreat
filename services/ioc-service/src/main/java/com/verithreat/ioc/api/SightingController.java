package com.verithreat.ioc.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.verithreat.ioc.api.Dtos.SightingRequest;
import com.verithreat.ioc.api.Dtos.SightingResponse;
import com.verithreat.ioc.service.SightingService;

import jakarta.validation.Valid;

/**
 * Aportación de IOCs por las organizaciones. La organización llega en la cabecera X-Organization; en el subpaso (b)
 * la pondrá el Gateway tras validar la clave de API, y el servicio no será accesible directamente.
 */
@RestController
@RequestMapping("/api/v1/sightings")
public class SightingController {

    private final SightingService service;

    public SightingController(SightingService service) {
        this.service = service;
    }

    /** 201 si es una aportación nueva de esa organización; 200 si ya la había aportado (se renueva). */
    @PostMapping
    public ResponseEntity<SightingResponse> submit(@RequestHeader("${verithreat.organization-header}") String organization,
                                                   @Valid @RequestBody SightingRequest request) {
        SightingResponse r = service.submit(organization, request);
        return ResponseEntity.status(r.created() ? HttpStatus.CREATED : HttpStatus.OK).body(r);
    }
}
