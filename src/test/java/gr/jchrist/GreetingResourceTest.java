package gr.jchrist;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.ws.rs.core.HttpHeaders;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;

@QuarkusTest
class GreetingResourceTest {
    @Test
    void testHelloEndpoint() {
        var body = given().when().header(HttpHeaders.AUTHORIZATION, "1").get("/hello").then().statusCode(200).extract().body().asString();
        Assertions.assertTrue(body.contains("RESTEasy Reactive: 1 running"), () -> "body not as expected: " + body);
        given().when().get("/hello").then().statusCode(401);
    }

    @Test
    void testHelloEndpoint1() {
        given().when().header(HttpHeaders.AUTHORIZATION, "1").get("/hello/1").then().statusCode(200);
    }

}