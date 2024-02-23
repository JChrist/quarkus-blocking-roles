package gr.jchrist;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
class GreetingResourceTest {
    @Test
    void testHelloEndpoint() {
        given().when().header(HttpHeaders.AUTHORIZATION, "1").get("/hello")
          .then()
             .statusCode(200);
    }

    @Test
    void testHelloEndpoint1() {
        given().when().header(HttpHeaders.AUTHORIZATION, "1").get("/hello/1")
          .then()
             .statusCode(200);
    }

}