package com.verithreat.ioc.fabric;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Activa la configuración de Fabric y la revisión periódica de la bandeja de salida. */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(FabricProperties.class)
public class FabricConfig {
}
