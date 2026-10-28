package com.verithreat.ioc.fabric;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuración del registro en Fabric (verithreat.fabric en application.yml).
 *
 * <p>Simplificación del TFM: el servicio guarda la identidad (certificado y clave privada) de cada organización y firma
 * en su nombre. En un despliegue real cada organización firmaría con su propia clave, que nunca saldría de su lado.
 *
 * @param enabled       false = las aportaciones se quedan en la bandeja de salida sin enviarse (se envían al activarlo)
 * @param pollInterval  cada cuánto se revisa la bandeja de salida
 * @param batchSize     máximo de registros por revisión
 * @param retryBase     espera tras el primer fallo; se duplica en cada intento hasta retryMax
 * @param organizations código de la organización (tabla source) → su identidad en Fabric
 */
@ConfigurationProperties("verithreat.fabric")
public record FabricProperties(boolean enabled, String channel, String chaincode, Duration pollInterval, int batchSize,
                               Duration retryBase, Duration retryMax, Map<String, Org> organizations) {

    /**
     * Identidad y peer de una organización.
     *
     * @param privateKey       fichero PEM de la clave, o el directorio keystore/ que la contiene (un único fichero)
     * @param peerEndpoint     host:puerto del peer de su organización (el Gateway de Fabric reparte los avales)
     * @param peerHostOverride nombre del certificado TLS del peer (localhost no coincide con él en la red de prueba)
     */
    public record Org(String mspId, Path certificate, Path privateKey, String peerEndpoint, String peerHostOverride,
                      Path tlsCaCertificate) {
    }

    public FabricProperties {
        organizations = organizations == null ? Map.of() : Map.copyOf(organizations);
    }
}
