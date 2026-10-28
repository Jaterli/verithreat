package com.verithreat.ioc.fabric;

/**
 * Fallo al hablar con Fabric. {@code permanent} = no tiene sentido reintentar (el chaincode rechazó los datos o la
 * organización no tiene identidad configurada); si no, es transitorio (red caída, plazo agotado, conflicto al validar).
 */
public class RegistryException extends Exception {

    private final boolean permanent;

    public RegistryException(String message, boolean permanent, Throwable cause) {
        super(message, cause);
        this.permanent = permanent;
    }

    public boolean permanent() {
        return permanent;
    }
}
