package com.thegamecellar.apigateway.controller;

/**
 * What the browser left for, remembered across the redirect. Everything but LOGIN forces a
 * fresh authentication; the two with a Keycloak action name let Keycloak own the form.
 */
public enum AuthIntent {
    LOGIN(null, null),
    UPDATE_PASSWORD("UPDATE_PASSWORD", "password"),
    UPDATE_EMAIL("UPDATE_EMAIL", "email"),
    DELETE_ACCOUNT(null, "delete");

    final String keycloakAction;
    final String landingAction;

    AuthIntent(String keycloakAction, String landingAction) {
        this.keycloakAction = keycloakAction;
        this.landingAction = landingAction;
    }

    // Anything unrecognised is a plain login, which grants nothing the caller did not already have.
    public static AuthIntent from(String raw) {
        if (raw == null) return LOGIN;
        for (AuthIntent intent : values()) {
            if (intent.name().equalsIgnoreCase(raw)) return intent;
        }
        return LOGIN;
    }

    // An action on an existing account, as opposed to a login or sign-up by someone unknown.
    public boolean isAccountAction() {
        return this != LOGIN;
    }
}
