package gr.jchrist;

import io.quarkus.panache.common.Parameters;
import io.quarkus.runtime.BlockingOperationControl;
import io.smallrye.common.annotation.Blocking;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import jakarta.annotation.security.RolesAllowed;
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

    // @Blocking // this fails with IllegalStateException: Wrong usage(s) of @Blocking found
    // returning Optional<Response> will not help either
    // if this is not enabled, then the `filterAfterMatch` is never reached, the request is rejected before it is called.
    // @ServerRequestFilter(preMatching = true)
    /* public Uni<Void> filter(ContainerRequestContext requestContext) {
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
    } */

    @ServerRequestFilter()
    public Optional<Response> filterAfterMatch(ContainerRequestContext requestContext) {
        MySecurityContext securityContext = null;
        MyEntity myEntity = null;
        if (requestContext.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            myEntity = fetchMyEntity(requestContext.getHeaderString(HttpHeaders.AUTHORIZATION));
            if (myEntity != null) {
                securityContext = createSecurityContext(myEntity);
            }
        }
        if (resourceInfo == null || resourceInfo.getResourceClass() == null || resourceInfo.getResourceMethod() == null) {
            logger.error("resource info injection failed!");
            return Optional.of(Response.serverError().build());
        }
        Set<String> roles = new HashSet<>();
        if (resourceInfo.getResourceClass().isAnnotationPresent(RolesAllowed.class)) {
            var classRoles = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class).value();
            roles.addAll(Set.of(classRoles));
        }
        if (resourceInfo.getResourceMethod().isAnnotationPresent(RolesAllowed.class)) {
            var methodRoles = resourceInfo.getResourceMethod().getAnnotation(RolesAllowed.class).value();
            roles.addAll(Set.of(methodRoles));
        }
        if (!roles.isEmpty()) {
            if (securityContext == null) {
                logger.error("Sending unauthorized response as there are roles required and no user: {}", roles);
                return Optional.of(Response.status(Response.Status.UNAUTHORIZED).build());
            }
            for (var role : roles) {
                var check = checkRole(myEntity.id, role);
                if (!check) {
                    return Optional.of(Response.status(Response.Status.FORBIDDEN).build());
                }
            }
            securityContext.roles.addAll(roles);
        }
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
        }

        @Override
        public Principal getUserPrincipal() {
            return () -> Long.toString(entity.id);
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
