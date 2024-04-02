package gr.jchrist;

import io.quarkus.panache.common.Parameters;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.security.spi.runtime.BlockingSecurityExecutor;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@ApplicationScoped
public class AugmentorPolicy implements HttpSecurityPolicy {
    private static final Logger logger = LoggerFactory.getLogger(AugmentorPolicy.class);

    @Inject ResourceInfo resourceInfo;
    @Inject BlockingSecurityExecutor blockingExecutor;

    @Override
    public Uni<CheckResult> checkPermission(RoutingContext request, Uni<SecurityIdentity> identity, AuthorizationRequestContext requestContext) {
        logger.info("augmentor check permission");
        return blockingExecutor.executeBlocking(() -> {
            // TODO: DO YOUR BLOCKING STUFF
            logger.info("Matched resource method is {}", resourceInfo.getResourceMethod());
            if (resourceInfo == null || resourceInfo.getResourceClass() == null || resourceInfo.getResourceMethod() == null) {
                logger.error("resource info injection in augmentor policy failed! {}", resourceInfo);
                // return Optional.of(Response.serverError().build());
                return new CheckResult(false);
            }
            MyEntity myEntity = null;
            logger.warn("checking for auth header: {}", request.request().headers());
            if (request.request().headers().contains(HttpHeaders.AUTHORIZATION)) {
                myEntity = fetchMyEntity(request.request().getHeader(HttpHeaders.AUTHORIZATION));
                /* if (myEntity != null) {
                    // final var sc = createSecurityContext(myEntity);
                    sc = createSecurityContext(myEntity);
                    // request.setSecurityContext(sc);
                } */
            }
            final Set<String> roles = new HashSet<>();
            if (resourceInfo.getResourceClass().isAnnotationPresent(RolesAllowed.class)) {
                var classRoles = resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class).value();
                roles.addAll(Set.of(classRoles));
            }
            if (resourceInfo.getResourceMethod().isAnnotationPresent(RolesAllowed.class)) {
                var methodRoles = resourceInfo.getResourceMethod().getAnnotation(RolesAllowed.class).value();
                roles.addAll(Set.of(methodRoles));
            }
            SecurityIdentity id = identity.await().indefinitely();
            if (!roles.isEmpty()) {
                if (myEntity == null) {
                    logger.warn("we have roles but no security context: {}", roles);
                    return new CheckResult(false);
                }
                for (var role : roles) {
                    var check = checkRole(myEntity.id, role);
                    if (!check) {
                        logger.warn("we have roles and sc but not matched: {}", role);
                        //return Optional.of(Response.status(Response.Status.FORBIDDEN).build());
                        return new CheckResult(false);
                    }
                }
            }
            if (myEntity != null) {
                logger.warn("returning id: {}", myEntity);
                id = QuarkusSecurityIdentity.builder(id).addRoles(roles).setPrincipal(myEntity).build();
            }

            return new CheckResult(true, id);
        });
    }

    @Override
    public String name() {
        return "augmentor";
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

    public MyFilter.MySecurityContext createSecurityContext(MyEntity myEntity) {
        return new MyFilter.MySecurityContext(myEntity);
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