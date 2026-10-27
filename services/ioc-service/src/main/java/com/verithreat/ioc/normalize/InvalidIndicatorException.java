package com.verithreat.ioc.normalize;

/** El valor no es un indicador válido para su tipo (se responde 400). */
public class InvalidIndicatorException extends RuntimeException {

    public InvalidIndicatorException(String message) {
        super(message);
    }
}
