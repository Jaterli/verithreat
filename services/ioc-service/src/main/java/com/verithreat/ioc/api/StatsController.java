package com.verithreat.ioc.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.verithreat.ioc.api.Dtos.Stats;
import com.verithreat.ioc.repo.StatsRepository;

/** Agregados para el panel general del dashboard: severidad por categoría, frescura de las fuentes, Fabric y modelo. */
@RestController
public class StatsController {

    private final StatsRepository repo;

    public StatsController(StatsRepository repo) {
        this.repo = repo;
    }

    @GetMapping("/api/v1/stats")
    public Stats stats() {
        return repo.stats();
    }
}
