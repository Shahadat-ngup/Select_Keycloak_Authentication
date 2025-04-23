package com.example.auth;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import jakarta.ws.rs.core.Response;

public class AuthSelectorAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Show selector only after username/password
        Response challenge = context.form()
            .setAttribute("username", context.getUser().getUsername())
            .createForm("auth-selector.ftl");
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        String method = context.getHttpRequest().getDecodedFormParameters().getFirst("method");

        if (method == null || method.isEmpty()) {
            showError(context, "Please select an authentication method");
            return;
        }

        switch (method.toLowerCase()) {
            case "otp":
                triggerOTP(context);
                break;
                
            case "email":
                triggerEmailVerification(context);
                break;
                
            case "webauthn":
                triggerWebAuthn(context);
                break;
                
            default:
                showError(context, "Invalid authentication method");
        }
    }

    private void triggerOTP(AuthenticationFlowContext context) {
        context.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
        context.success();
    }

    private void triggerEmailVerification(AuthenticationFlowContext context) {
        context.getAuthenticationSession().addRequiredAction(UserModel.RequiredAction.VERIFY_EMAIL);
        context.success();
    }

    private void triggerWebAuthn(AuthenticationFlowContext context) {
        context.getAuthenticationSession().addRequiredAction("webauthn-register");
        context.success();
    }

    private void showError(AuthenticationFlowContext context, String error) {
        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
            context.form()
                .setError(error)
                .createForm("auth-selector.ftl"));
    }

    @Override
    public boolean requiresUser() {
        return true; // Requires successful username/password first
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No additional setup needed
    }

    @Override
    public void close() {
    }
}