package com.verithreat.ioc.fabric;

import java.time.Instant;

/** Registro que guarda el chaincode iocregistry (blockchain/chaincode/iocregistry), tal como lo devuelve en JSON. */
public record RegistryRecord(String canonicalHash, String type, String indicatorFingerprint, String category,
                             String mspId, Instant registeredAt, String txId) {
}
