package packetanalyzer.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Serves the plain HTML/CSS/JavaScript web dashboard assets.
 * Looks for static files in classpath resources (/dashboard/*) first,
 * with fallback to filesystem locations (./dashboard/*).
 */
public class DashboardHandler implements HttpHandler {

    private static final Logger logger = LoggerFactory.getLogger(DashboardHandler.class);

    private final String filesystemBasePath;

    public DashboardHandler(String filesystemBasePath) {
        this.filesystemBasePath = filesystemBasePath;
    }

    public DashboardHandler() {
        this("dashboard");
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();

        if (path.equals("/") || path.isEmpty()) {
            path = "/index.html";
        }

        String resourceName = path.startsWith("/") ? path.substring(1) : path;
        String contentType = getContentType(resourceName);

        byte[] content = loadResource(resourceName);
        if (content == null) {
            String notFoundMsg = "404 Not Found: " + resourceName;
            exchange.sendResponseHeaders(404, notFoundMsg.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(notFoundMsg.getBytes(StandardCharsets.UTF_8));
            }
            return;
        }

        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(200, content.length);

        try (OutputStream os = exchange.getResponseBody()) {
            os.write(content);
        }
    }

    private byte[] loadResource(String filename) {
        // 1. Try Classpath (/dashboard/filename)
        String cpPath = "/dashboard/" + filename;
        try (InputStream is = getClass().getResourceAsStream(cpPath)) {
            if (is != null) {
                return is.readAllBytes();
            }
        } catch (IOException ignored) {}

        // 2. Try configured filesystem location
        File[] candidates = new File[] {
            new File(filesystemBasePath, filename),
            new File("dashboard", filename),
            new File("java/dashboard", filename),
            new File("../java/dashboard", filename),
            new File("Packet_analyzer-main/java/dashboard", filename)
        };

        for (File candidate : candidates) {
            if (candidate.exists() && candidate.isFile()) {
                try (InputStream fis = new FileInputStream(candidate)) {
                    return fis.readAllBytes();
                } catch (IOException ignored) {}
            }
        }

        logger.debug("Dashboard asset not found: {}", filename);
        return null;
    }

    private String getContentType(String filename) {
        if (filename.endsWith(".html") || filename.endsWith(".htm")) {
            return "text/html; charset=UTF-8";
        } else if (filename.endsWith(".css")) {
            return "text/css; charset=UTF-8";
        } else if (filename.endsWith(".js")) {
            return "application/javascript; charset=UTF-8";
        } else if (filename.endsWith(".json")) {
            return "application/json; charset=UTF-8";
        } else if (filename.endsWith(".svg")) {
            return "image/svg+xml";
        } else if (filename.endsWith(".ico")) {
            return "image/x-icon";
        }
        return "text/plain; charset=UTF-8";
    }
}
