package gr.jchrist;

import io.quarkus.panache.common.Parameters;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@ApplicationScoped
public class MyFilter {
    private static final Logger logger = LoggerFactory.getLogger(MyFilter.class);

    @Inject Vertx vertx;
    @Inject ResourceInfo resourceInfo;
    @Inject SecurityIdentity securityIdentity;

    // if this is enabled/active, then @Inject-ed ResourceInfo inside AugmentorPolicy contains null class/method
    @ServerRequestFilter(preMatching = true)
    public Uni<Void> filter(ContainerRequestContext requestContext) {
        logger.info("inside pre-matching filter");
        return vertx.executeBlocking(() -> {
            if (requestContext.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                var myEntity = fetchMyEntity(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION));
                if (myEntity != null) {
                    final var sc = createSecurityContext(myEntity);
                    requestContext.setSecurityContext(sc);
                }
                if (resourceInfo == null || resourceInfo.getResourceClass() == null || resourceInfo.getResourceMethod() == null) {
                    logger.error("resource info injection failed in pre-matching!");
                    return null;
                }
            }
            return null;
        });
    }

    @ServerRequestFilter
    public Optional<Response> filterAfterMatch(ContainerRequestContext requestContext) {
        logger.info("inside post-match filter, identity is:{} sc principal is:{}", securityIdentity, requestContext.getSecurityContext().getUserPrincipal());
        if (securityIdentity == null || securityIdentity.isAnonymous()) {
            logger.warn("inside post-match filter, security identity is null/anonymous");
            return Optional.empty();
        }
        /* var principal = (MyEntity) securityIdentity.getPrincipal();
        var roles = securityIdentity.getRoles();
        requestContext.setSecurityContext(new MySecurityContext(principal, roles));
        logger.warn("security identity contains principal: {} and roles:{}", principal, roles); */
        return Optional.empty();
    }

    @Transactional
    public MyEntity fetchMyEntity(String auth) {
        try {
            long id = Long.parseLong(auth);
            final MyEntity myEntity = MyEntity.findById(id);
            MyEntity.getEntityManager().detach(myEntity);
            return myEntity;
        } catch (Exception e) {
            logger.warn("exception", e);
            return null;
        }
    }

    public MySecurityContext createSecurityContext(MyEntity myEntity) {
        return new MySecurityContext(myEntity);
    }

    @Transactional
    public boolean checkRole(long id, String role) {
        logger.info("checking role: {} for id:{}", role, id);
        return MyEntity.find("id=:id AND field=:role", Parameters.with("id", id).and("role", role)).firstResultOptional().isPresent();
    }

    public record MySecurityContext(MyEntity entity, Set<String> roles) implements SecurityContext {
        public MySecurityContext(MyEntity myEntity) {
            this(myEntity, new HashSet<>());
            // this(myEntity, new HashSet<>());
        }

        @Override
        public Principal getUserPrincipal() {
            return entity;
        }

        @Override
        public boolean isUserInRole(String role) {
            return roles.contains(role);
        }

        @Override
        public boolean isSecure() {
            return true;
        }

        @Override
        public String getAuthenticationScheme() {
            return SecurityContext.BASIC_AUTH;
        }
    }
}
