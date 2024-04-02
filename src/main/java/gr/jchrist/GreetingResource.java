package gr.jchrist;

import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;

@Path("/hello")
public class GreetingResource {
    @Inject SecurityContext sc;

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @RolesAllowed("field-1")
    public String hello() {
        String usr;
        if (sc == null) {
            usr = "<null sc>";
        } else if (sc.getUserPrincipal() == null) {
            usr = "<null principal>";
        } else {
            usr = sc.getUserPrincipal().getName();
        }
        //var usr = sc != null ? sc.getUserPrincipal() : null;
        return "Hello from RESTEasy Reactive: " + usr + " running on thread: " + Thread.currentThread().getName();
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    @Path("/1")
    public String hello1() {
        var usr = sc != null ? sc.getUserPrincipal() : null;
        return "Hello1 " + (usr == null ? "<null>" : usr.getName()) + " running on thread: " + Thread.currentThread().getName();
    }
}
