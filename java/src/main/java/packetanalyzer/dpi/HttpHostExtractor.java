package packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Extracts the "Host:" header from unencrypted HTTP/1.x requests.
 * Mirrors the C++ HTTPHostExtractor class in sni_extractor.cpp.
 */
public final class HttpHostExtractor {

    private static final String[] HTTP_METHODS = {
        "GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"
    };

    private HttpHostExtractor() {
        // Utility
    }

    /**
     * Checks if the payload begins with a common HTTP request method.
     */
    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (payload == null || length < 4 || offset + 4 > payload.length) {
            return false;
        }

        String prefix = new String(payload, offset, 4, StandardCharsets.US_ASCII);
        for (String method : HTTP_METHODS) {
            if (prefix.equals(method)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the Host header value (excluding optional port) from an HTTP request.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) {
            return Optional.empty();
        }

        int end = offset + length;
        // Search for "Host:" case-insensitively
        for (int i = offset; i + 5 < end; i++) {
            if ((payload[i] == 'H' || payload[i] == 'h') &&
                (payload[i + 1] == 'o' || payload[i + 1] == 'O') &&
                (payload[i + 2] == 's' || payload[i + 2] == 'S') &&
                (payload[i + 3] == 't' || payload[i + 3] == 'T') &&
                payload[i + 4] == ':') {

                int start = i + 5;
                // Skip leading spaces / tabs
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find line terminator (\r or \n)
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start, StandardCharsets.US_ASCII).trim();
                    // Strip port if present (e.g. "example.com:8080" -> "example.com")
                    int colonIndex = host.indexOf(':');
                    if (colonIndex != -1) {
                        host = host.substring(0, colonIndex);
                    }
                    if (!host.isEmpty()) {
                        return Optional.of(host);
                    }
                }
            }
        }

        return Optional.empty();
    }

    public static Optional<String> extract(byte[] payload) {
        if (payload == null) return Optional.empty();
        return extract(payload, 0, payload.length);
    }
}
