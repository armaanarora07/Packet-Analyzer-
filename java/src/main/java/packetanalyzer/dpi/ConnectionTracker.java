package packetanalyzer.dpi;

import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.model.ConnectionState;
import packetanalyzer.model.FiveTuple;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Maintains the active connection / flow table.
 * Supports bidirectional flow correlation (matching forward and reverse FiveTuple).
 *
 * <p>Direct equivalent of the C++ {@code ConnectionTracker} class.</p>
 */
public class ConnectionTracker {

    private final int trackerId;
    private final int maxConnections;
    private final Map<FiveTuple, Connection> connections;

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int trackerId, int maxConnections) {
        this.trackerId = trackerId;
        this.maxConnections = maxConnections;
        this.connections = new ConcurrentHashMap<>();
    }

    public ConnectionTracker() {
        this(0, 100_000);
    }

    /**
     * Retrieves an existing connection or creates a new flow record.
     * Also checks the reverse FiveTuple to ensure bidirectional packets map to the same session.
     */
    public synchronized Connection getOrCreateConnection(FiveTuple tuple) {
        Connection existing = getConnection(tuple);
        if (existing != null) {
            return existing;
        }

        if (connections.size() >= maxConnections) {
            evictOldest();
        }

        Connection conn = new Connection(tuple);
        connections.put(tuple, conn);
        totalSeen++;
        return conn;
    }

    /**
     * Looks up an existing connection matching either forward or reverse tuple.
     *
     * @return Existing {@link Connection}, or {@code null} if not found
     */
    public Connection getConnection(FiveTuple tuple) {
        if (tuple == null) return null;
        Connection conn = connections.get(tuple);
        if (conn != null) {
            return conn;
        }
        // Bidirectional matching: check reverse tuple
        return connections.get(tuple.reverse());
    }

    /**
     * Updates traffic volume and timestamp for the specified connection.
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn != null) {
            conn.update(packetSize, isOutbound);
        }
    }

    /**
     * Sets the classified application type and SNI hostname.
     */
    public synchronized void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn != null && conn.getState() != ConnectionState.CLASSIFIED) {
            conn.classify(app, sni);
            classifiedCount++;
        }
    }

    /**
     * Marks a connection as blocked.
     */
    public synchronized void blockConnection(Connection conn) {
        if (conn != null) {
            conn.block();
            blockedCount++;
        }
    }

    /**
     * Marks a connection as closed.
     */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = getConnection(tuple);
        if (conn != null) {
            conn.close();
        }
    }

    /**
     * Purges stale or closed connections exceeding the inactivity timeout.
     *
     * @param timeout Inactivity threshold
     * @return Number of connections removed
     */
    public synchronized int cleanupStale(Duration timeout) {
        Instant now = Instant.now();
        List<FiveTuple> toRemove = new ArrayList<>();

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            Connection conn = entry.getValue();
            Duration idle = Duration.between(conn.getLastSeen(), now);
            if (idle.compareTo(timeout) > 0 || conn.getState() == ConnectionState.CLOSED) {
                toRemove.add(entry.getKey());
            }
        }

        for (FiveTuple tuple : toRemove) {
            connections.remove(tuple);
        }
        return toRemove.size();
    }

    private void evictOldest() {
        if (connections.isEmpty()) return;
        FiveTuple oldestKey = null;
        Instant oldestTime = Instant.MAX;

        for (Map.Entry<FiveTuple, Connection> entry : connections.entrySet()) {
            if (entry.getValue().getLastSeen().isBefore(oldestTime)) {
                oldestTime = entry.getValue().getLastSeen();
                oldestKey = entry.getKey();
            }
        }
        if (oldestKey != null) {
            connections.remove(oldestKey);
        }
    }

    public List<Connection> getAllConnections() {
        return new ArrayList<>(connections.values());
    }

    public int getActiveCount() {
        return connections.size();
    }

    public void forEach(Consumer<Connection> consumer) {
        connections.values().forEach(consumer);
    }

    public synchronized void clear() {
        connections.clear();
        totalSeen = 0;
        classifiedCount = 0;
        blockedCount = 0;
    }

    public record TrackerStats(
        int activeConnections,
        long totalSeen,
        long classifiedCount,
        long blockedCount
    ) {}

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }
}
