package de.ctrlaltdel;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wildfly.extension.undertow.security.AccountImpl;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.Serializable;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.security.api.SecurityContext;
import io.undertow.security.idm.Account;
import io.undertow.security.idm.IdentityManager;
import io.undertow.server.HttpServerExchange;
import io.undertow.server.handlers.form.FormParserFactory;
import io.undertow.servlet.handlers.ServletRequestContext;
import net.sourceforge.spnego.SpnegoAuthenticator;
import net.sourceforge.spnego.SpnegoPrincipal;

/**
 * SpnegoHandler
 */
public class SpnegoAuthenticationMechanism implements AuthenticationMechanism {

    private static final Logger LOG = LoggerFactory.getLogger(SpnegoAuthenticationMechanism.class);

    private final SpnegoAuthenticator authenticator;
    private final String mechanismName;

    static final long UPTIME = System.currentTimeMillis();

    private SpnegoAuthenticationMechanism(String mechanismName) {
        try {
            this.authenticator = new SpnegoAuthenticator();
            LOG.info("Spnego-Auth started");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        this.mechanismName = mechanismName;

    }


    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {

        ServletRequestContext servletRequestContext = exchange.getAttachment(ServletRequestContext.ATTACHMENT_KEY);
        HttpServletRequest request = servletRequestContext.getOriginalRequest();
        HttpServletResponse response = servletRequestContext.getOriginalResponse();

        String accountName;
        try {
            SpnegoPrincipal principal = this.authenticator.authenticate(request, response);
            accountName = principal == null ? null : principal.getName();
        } catch (Exception gsse) {
            LOG.error("HTTP Authorization Header=" + request.getHeader("Authorization"));
            return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
        }

        if (accountName == null) {
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        SimplePrincipal principal = new SimplePrincipal(accountName, String.valueOf(System.currentTimeMillis()));

        IdentityManager identityManager = securityContext.getIdentityManager();
        Account account = identityManager.verify(new AccountImpl(principal, Collections.<String>emptySet(), principal.getCredential()));
        if (account == null) {
            return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
        }

        securityContext.authenticationComplete(account, mechanismName, true);

        LOG.debug("authentificated {}", principal);

        return AuthenticationMechanismOutcome.AUTHENTICATED;

    }


    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        return new ChallengeResult(true, HttpServletResponse.SC_UNAUTHORIZED);
    }

    public static final class Factory implements AuthenticationMechanismFactory {
        @Override
        public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
            return new SpnegoAuthenticationMechanism(mechanismName);
        }
    }

    public static class SimplePrincipal implements Principal, Serializable {
        private final String name;
        private final String credential;
        public SimplePrincipal(String name, String credential) {
            this.credential = credential;
            int idx = name.indexOf('@');
            this.name = 0 < idx ? name.substring(0, idx) : name;
        }

        @Override
        public String getName() {
            return name;
        }

        public String getCredential() {
            return credential;
        }

        @Override
        public String toString() {
            return name;
        }
    }


}
