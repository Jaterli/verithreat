package com.verithreat.ioc.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.verithreat.ioc.normalize.InvalidIndicatorException;
import com.verithreat.ioc.service.UnknownOrganizationException;

/** Errores como application/problem+json (RFC 9457). */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(InvalidIndicatorException.class)
    public ProblemDetail invalid(InvalidIndicatorException e) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
        p.setTitle("Invalid indicator");
        return p;
    }

    @ExceptionHandler(UnknownOrganizationException.class)
    public ProblemDetail unknownOrganization(UnknownOrganizationException e) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, e.getMessage());
        p.setTitle("Unknown organization");
        return p;
    }

    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ProblemDetail constraint(jakarta.validation.ConstraintViolationException e) {
        ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
        p.setTitle("Invalid parameter");
        return p;
    }

    @Override
    protected org.springframework.http.ResponseEntity<Object> handleServletRequestBindingException(
            org.springframework.web.bind.ServletRequestBindingException ex, org.springframework.http.HttpHeaders headers,
            org.springframework.http.HttpStatusCode status, org.springframework.web.context.request.WebRequest request) {
        if (ex instanceof MissingRequestHeaderException mh) { // sin X-Organization no se sabe quién aporta: 401
            ProblemDetail p = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED,
                    "missing header " + mh.getHeaderName());
            p.setTitle("Organization required");
            return org.springframework.http.ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(p);
        }
        return super.handleServletRequestBindingException(ex, headers, status, request);
    }
}
