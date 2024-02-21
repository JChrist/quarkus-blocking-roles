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
    @ServerRequestFilter(preMatching = true)
    public Uni<Void> filter(ContainerRequestContext requestContext) {
        return vertx.executeBlocking(() -> {
            if (requestContext.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                final var sc = createSecurityContext(requestContext, requestContext.getHeaderString(HttpHeaders.AUTHORIZATION));
                if (sc != null) {
                    requestContext.setSecurityContext(sc);
                }
            }
            return null;
        });
    }

    @ServerRequestFilter()
    public Optional<Response> filterAfterMatch(ContainerRequestContext requestContext) {
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
            for (var role : roles) {
                logger.warn("second attempt to actually check role: {} for user:{}", role, requestContext.getSecurityContext().getUserPrincipal().getName());
                if (!requestContext.getSecurityContext().isUserInRole(role)) {
                    return Optional.of(Response.status(Response.Status.FORBIDDEN).build());
                }
            }
        }
        return Optional.empty();
    }

    @Transactional
    public SecurityContext createSecurityContext(ContainerRequestContext requestContext, String auth) {
        try {
            long id = Long.parseLong(auth);
            final MyEntity myEntity = MyEntity.findById(id);
            MyEntity.getEntityManager().detach(myEntity);
            return new SecurityContext() {
                @Override
                public Principal getUserPrincipal() {
                    return () -> Long.toString(id);
                }

                @Override
                public boolean isUserInRole(String role) {
                    if (!BlockingOperationControl.isBlockingAllowed()) {
                        logger.error("LYING THAT user:{} has role:{} AS I CANNOT BLOCK!", id, role);
                        return true;
                    }
                    return checkRole(myEntity.id, role);
                }

                @Override
                public boolean isSecure() {
                    return requestContext.getSecurityContext().isSecure();
                }

                @Override
                public String getAuthenticationScheme() {
                    return SecurityContext.BASIC_AUTH;
                }
            };
        } catch (Exception e) {
            logger.warn("exception", e);
            return null;
        }
    }

    @Transactional
    public boolean checkRole(long id, String role) {
        logger.info("checking role: {} for id:{}", role, id);
        return MyEntity.find("id=:id AND field=:role", Parameters.with("id", id).and("role", role)).firstResultOptional().isPresent();
    }
}
