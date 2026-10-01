package packetanalyzer.api;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import packetanalyzer.dpi.ConnectionTracker;
import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.model.ConnectionState;
import packetanalyzer.model.FiveTuple;
import packetanalyzer.model.PacketAction;
import packetanalyzer.stats.DpiStatistics;
import packetanalyzer.stats.DpiStatsService;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

class ApiServerTest {

    private static ApiServer server;
    private static HttpClient client;
    private static String baseUrl;

    @BeforeAll
    static void setUp() throws IOException {
        DpiStatistics stats = new DpiStatistics();
        ConnectionTracker tracker = new ConnectionTracker();
        DpiStatsService statsService = new DpiStatsService(stats, tracker);

        // Add dummy data for inspection
        FiveTuple tuple = new FiveTuple("192.168.1.50", "172.217.16.206", 52100, 443, 6);
        Connection conn = tracker.getOrCreateConnection(tuple);
        conn.setAppType(AppType.YOUTUBE);
        conn.setSni("youtube.com");
        conn.setState(ConnectionState.ESTABLISHED);
        conn.setAction(PacketAction.FORWARD);
        conn.update(1400, true);

        stats.recordPacket(1400, true, false);
        stats.recordForwarded();
        stats.setActiveConnections(1);

        // Port 0 binds to any available ephemeral port
        server = new ApiServer(statsService, 0);
        server.start();

        baseUrl = server.getBaseUrl();
        client = HttpClient.newHttpClient();
    }

    @AfterAll
    static void tearDown() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void testGetStatsEndpoint() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/stats"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).hasValue("application/json; charset=UTF-8");
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue("*");

        String body = response.body();
        assertThat(body).contains("\"totalPackets\": 1");
        assertThat(body).contains("\"forwardedPackets\": 1");
        assertThat(body).contains("\"droppedPackets\": 0");
        assertThat(body).contains("\"applicationDistribution\":");
        assertThat(body).contains("\"YouTube\": 1");
    }

    @Test
    void testGetFlowsEndpoint() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/flows"))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).hasValue("application/json; charset=UTF-8");
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue("*");

        String body = response.body();
        assertThat(body).contains("\"srcIp\": \"192.168.1.50\"");
        assertThat(body).contains("\"dstIp\": \"172.217.16.206\"");
        assertThat(body).contains("\"srcPort\": 52100");
        assertThat(body).contains("\"dstPort\": 443");
        assertThat(body).contains("\"protocol\": \"TCP\"");
        assertThat(body).contains("\"application\": \"YouTube\"");
        assertThat(body).contains("\"sni\": \"youtube.com\"");
        assertThat(body).contains("\"state\": \"ESTABLISHED\"");
    }

    @Test
    void testCorsOptionsRequest() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/stats"))
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(204);
        assertThat(response.headers().firstValue("Access-Control-Allow-Origin")).hasValue("*");
        assertThat(response.headers().firstValue("Access-Control-Allow-Methods")).hasValue("GET, OPTIONS");
    }

    @Test
    void testMethodNotAllowed() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/api/stats"))
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .build();

        HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
        assertThat(response.statusCode()).isEqualTo(405);
    }

    @Test
    void testDashboardStaticFiles() throws Exception {
        // Test root serving index.html
        HttpRequest reqRoot = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/"))
                .GET()
                .build();
        HttpResponse<String> resRoot = client.send(reqRoot, HttpResponse.BodyHandlers.ofString());
        assertThat(resRoot.statusCode()).isEqualTo(200);
        assertThat(resRoot.headers().firstValue("Content-Type")).hasValue("text/html; charset=UTF-8");
        assertThat(resRoot.body()).contains("DPI Engine Dashboard");

        // Test style.css
        HttpRequest reqCss = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/style.css"))
                .GET()
                .build();
        HttpResponse<String> resCss = client.send(reqCss, HttpResponse.BodyHandlers.ofString());
        assertThat(resCss.statusCode()).isEqualTo(200);
        assertThat(resCss.headers().firstValue("Content-Type")).hasValue("text/css; charset=UTF-8");
        assertThat(resCss.body()).contains("--bg-base");

        // Test app.js
        HttpRequest reqJs = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/app.js"))
                .GET()
                .build();
        HttpResponse<String> resJs = client.send(reqJs, HttpResponse.BodyHandlers.ofString());
        assertThat(resJs.statusCode()).isEqualTo(200);
        assertThat(resJs.headers().firstValue("Content-Type")).hasValue("application/javascript; charset=UTF-8");
        assertThat(resJs.body()).contains("fetchDashboardData");
    }

    @Test
    void testNotFoundStaticFile() throws Exception {
        HttpRequest reqNotFound = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/nonexistent-page.html"))
                .GET()
                .build();
        HttpResponse<String> resNotFound = client.send(reqNotFound, HttpResponse.BodyHandlers.ofString());
        assertThat(resNotFound.statusCode()).isEqualTo(404);
    }
}
