package packetanalyzer.api;

import com.sun.net.httpserver.HttpServer;
import packetanalyzer.stats.DpiStatsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Embedded HTTP Server built on JDK's built-in {@link HttpServer}.
 * Exposes REST API endpoints (/api/stats, /api/flows) and serves the static Web Dashboard.
 *
 * <p>Zero external web frameworks required.</p>
 */
public class ApiServer {

    private static final Logger logger = LoggerFactory.getLogger(ApiServer.class);

    private final DpiStatsService statsService;
    private final int requestedPort;
    private HttpServer server;
    private int actualPort;
    private boolean running = false;

    public ApiServer(DpiStatsService statsService, int port) {
        this.statsService = statsService;
        this.requestedPort = port;
    }

    public ApiServer(DpiStatsService statsService) {
        this(statsService, 8080);
    }

    /**
     * Initializes and starts the HTTP server.
     */
    public synchronized void start() throws IOException {
        if (running) {
            return;
        }

        server = HttpServer.create(new InetSocketAddress(requestedPort), 0);
        actualPort = server.getAddress().getPort();

        // Register API Routes
        server.createContext("/api/stats", new StatsApiHandler(statsService));
        server.createContext("/api/flows", new FlowsApiHandler(statsService));

        // Register Static Dashboard Handler
        server.createContext("/", new DashboardHandler());

        // Default thread executor for handling requests
        server.setExecutor(Executors.newFixedThreadPool(6));
        server.start();
        running = true;

        logger.info("DPI REST API Server started at http://localhost:{}/", actualPort);
    }

    /**
     * Stops the HTTP server immediately.
     */
    public synchronized void stop() {
        if (!running || server == null) {
            return;
        }
        server.stop(0);
        running = false;
        logger.info("DPI REST API Server stopped");
    }

    public int getPort() {
        return actualPort;
    }

    public String getBaseUrl() {
        return "http://localhost:" + actualPort;
    }

    public boolean isRunning() {
        return running;
    }
}
