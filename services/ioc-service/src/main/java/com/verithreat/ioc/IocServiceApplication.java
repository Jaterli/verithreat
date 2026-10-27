package com.verithreat.ioc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Servicio de IOCs de VeriThreat: consulta de indicadores y su severidad, y aportación de IOCs por parte de las
 * organizaciones. Lee y escribe la base de datos que alimenta el motor Python de ai/ (decisión 14 de CLAUDE.md).
 */
@SpringBootApplication
public class IocServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IocServiceApplication.class, args);
    }
}
