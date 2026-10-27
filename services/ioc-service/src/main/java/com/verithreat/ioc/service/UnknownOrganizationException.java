package com.verithreat.ioc.service;

/** La organización de la petición no está registrada como fuente de tipo 'organization' (se responde 403). */
public class UnknownOrganizationException extends RuntimeException {

    public UnknownOrganizationException(String organization) {
        super("unknown organization: " + organization);
    }
}
