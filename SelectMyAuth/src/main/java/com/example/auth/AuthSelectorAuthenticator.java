package com.example.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.Response;

public class AuthSelectorAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form()
                .setAttribute("username", context.getAuthenticationSession().getAuthNote(AuthenticationManager.FORM_USERNAME))
                .createForm("auth-selector.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String method = context.getHttpRequest().getDecodedFormParameters().getFirst("method");

        if (method == null || method.isEmpty()) {
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError("Please choose an authentication method").createForm("auth-selector.ftl"));
            return;
        }

        switch (method) {
            case "password":
                context.getAuthenticationSession().setAuthNote("SELECTED_METHOD", "password");
                context.success();
                break;
            case "otp":
                context.getAuthenticationSession().setAuthNote("SELECTED_METHOD", "otp");
                context.success();
                break;
            case "email":
                context.getAuthenticationSession().setAuthNote("SELECTED_METHOD", "email");
                context.success();
                break;
            case "webauthn":
                context.getAuthenticationSession().setAuthNote("SELECTED_METHOD", "webauthn");
                context.success();
                break;
            default:
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                        context.form().setError("Invalid method").createForm("auth-selector.ftl"));
        }
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}