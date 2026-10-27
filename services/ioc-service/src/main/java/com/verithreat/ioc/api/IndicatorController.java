package com.verithreat.ioc.api;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.verithreat.ioc.api.Dtos.IndicatorDetail;
import com.verithreat.ioc.api.Dtos.IndicatorRow;
import com.verithreat.ioc.api.Dtos.IndicatorView;
import com.verithreat.ioc.api.Dtos.Page;
import com.verithreat.ioc.normalize.InvalidIndicatorException;
import com.verithreat.ioc.normalize.Normalizer;
import com.verithreat.ioc.repo.IndicatorRepository;
import com.verithreat.ioc.repo.IndicatorRepository.IndicatorRecord;
import com.verithreat.ioc.service.SightingService;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

/** Consulta de indicadores: búsqueda por valor, listado priorizado y detalle. */
@RestController
@RequestMapping("/api/v1/indicators")
@Validated
public class IndicatorController {

    private final IndicatorRepository repo;

    public IndicatorController(IndicatorRepository repo) {
        this.repo = repo;
    }

    /** ¿Conocemos este IOC y cuánto riesgo tiene? El valor se normaliza antes de buscarlo. 404 si no se conoce. */
    @GetMapping("/lookup")
    public IndicatorView lookup(@RequestParam String type, @RequestParam String value) {
        String normalized = Normalizer.normalize(type, value);
        IndicatorRecord ind = repo.findByValue(type, normalized)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "indicator not found: " + type + " " + normalized));
        return view(ind);
    }

    /** Listado ordenado por severidad descendente, con filtros opcionales. */
    @GetMapping
    public Page<IndicatorRow> list(@RequestParam(required = false) String type,
                                   @RequestParam(required = false) String category,
                                   @RequestParam(defaultValue = "0") @Min(0) @Max(100) int minSeverity,
                                   @RequestParam(defaultValue = "0") @Min(0) int page,
                                   @RequestParam(defaultValue = "50") @Min(1) @Max(500) int size) {
        if (type != null && !Normalizer.TYPES.contains(type)) {
            throw new InvalidIndicatorException("unknown type: " + type);
        }
        if (category != null && !SightingService.CATEGORIES.contains(category)) {
            throw new InvalidIndicatorException("unknown category: " + category);
        }
        List<IndicatorRow> rows = repo.list(type, category, minSeverity, page, size);
        boolean hasNext = rows.size() > size;
        return new Page<>(hasNext ? rows.subList(0, size) : rows, page, size, hasNext);
    }

    /** Detalle: severidad y componentes, observaciones (las 200 más recientes) e historial de severidad (50). */
    @GetMapping("/{id}")
    public IndicatorDetail detail(@PathVariable long id) {
        IndicatorRecord ind = repo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "indicator not found: " + id));
        return new IndicatorDetail(view(ind), repo.sightings(id, 200), repo.scoreHistory(id, 50));
    }

    private IndicatorView view(IndicatorRecord ind) {
        return new IndicatorView(ind.id(), ind.type(), ind.value(), ind.fingerprint(),
                repo.currentScore(ind.id()).orElse(null), repo.summary(ind.id()));
    }
}
