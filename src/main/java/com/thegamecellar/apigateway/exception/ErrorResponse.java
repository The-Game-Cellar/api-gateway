package com.thegamecellar.apigateway.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.MDC;

import java.time.Instant;

public record ErrorResponse(
        String error,
        int status,
        String timestamp,
        String path,
        String requestId
) {
    public static ErrorResponse of(int status, String message, HttpServletRequest request) {
        String path = request != null ? request.getRequestURI() : null;
        return new ErrorResponse(message, status, Instant.now().toString(), path, MDC.get("requestId"));
    }
}
