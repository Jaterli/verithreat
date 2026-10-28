package com.verithreat.ioc.fabric;

import java.util.Optional;

/** El registro de procedencia en Fabric, visto desde ioc-service (implementación real: {@link FabricGatewayRegistry}). */
public interface IocRegistry {

    /** Registra la aportación firmando como la organización. Devuelve el registro creado por el chaincode. */
    RegistryRecord register(String organization, String type, String fingerprint, String category)
            throws RegistryException;

    /**
     * El registro que ya tenga en la cadena esta organización para este indicador (el más antiguo si hubiera varios).
     * Sirve para no registrar dos veces cuando la transacción llegó a Fabric pero no se pudo anotar en la base de datos.
     */
    Optional<RegistryRecord> find(String organization, String type, String fingerprint) throws RegistryException;
}
