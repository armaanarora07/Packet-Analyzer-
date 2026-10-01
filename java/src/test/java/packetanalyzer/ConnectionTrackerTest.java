package packetanalyzer;

import packetanalyzer.dpi.ConnectionTracker;
import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.model.ConnectionState;
import packetanalyzer.model.FiveTuple;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionTrackerTest {

    @Test
    void testConnectionCreationAndBidirectionalLookup() {
        ConnectionTracker tracker = new ConnectionTracker(0, 1000);

        FiveTuple clientToServer = new FiveTuple("192.168.1.100", "142.250.190.46", 54321, 443, 6);
        FiveTuple serverToClient = clientToServer.reverse();

        // 1. Create connection on outbound packet
        Connection conn1 = tracker.getOrCreateConnection(clientToServer);
        assertThat(conn1).isNotNull();
        assertThat(tracker.getActiveCount()).isEqualTo(1);

        // 2. Query connection using reverse tuple (inbound packet)
        Connection conn2 = tracker.getConnection(serverToClient);
        assertThat(conn2).isSameAs(conn1);

        // 3. getOrCreate with reverse tuple returns existing connection
        Connection conn3 = tracker.getOrCreateConnection(serverToClient);
        assertThat(conn3).isSameAs(conn1);
        assertThat(tracker.getActiveCount()).isEqualTo(1);
    }

    @Test
    void testConnectionMetricsUpdating() {
        ConnectionTracker tracker = new ConnectionTracker();
        FiveTuple tuple = new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 80, 6);
        Connection conn = tracker.getOrCreateConnection(tuple);

        tracker.updateConnection(conn, 100, true);  // 100 bytes outbound
        tracker.updateConnection(conn, 500, false); // 500 bytes inbound

        assertThat(conn.getPacketsOut()).isEqualTo(1);
        assertThat(conn.getPacketsIn()).isEqualTo(1);
        assertThat(conn.getTotalPackets()).isEqualTo(2);
        assertThat(conn.getBytesOut()).isEqualTo(100);
        assertThat(conn.getBytesIn()).isEqualTo(500);
        assertThat(conn.getTotalBytes()).isEqualTo(600);
    }

    @Test
    void testConnectionStateAndClassification() {
        ConnectionTracker tracker = new ConnectionTracker();
        FiveTuple tuple = new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 443, 6);
        Connection conn = tracker.getOrCreateConnection(tuple);

        assertThat(conn.getState()).isEqualTo(ConnectionState.NEW);

        tracker.classifyConnection(conn, AppType.YOUTUBE, "www.youtube.com");
        assertThat(conn.getState()).isEqualTo(ConnectionState.CLASSIFIED);
        assertThat(conn.getAppType()).isEqualTo(AppType.YOUTUBE);
        assertThat(conn.getSni()).isEqualTo("www.youtube.com");

        tracker.blockConnection(conn);
        assertThat(conn.getState()).isEqualTo(ConnectionState.BLOCKED);
        assertThat(conn.getAction()).isEqualTo(packetanalyzer.model.PacketAction.DROP);
    }

    @Test
    void testCleanupStale() {
        ConnectionTracker tracker = new ConnectionTracker();
        FiveTuple tuple = new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 443, 6);
        Connection conn = tracker.getOrCreateConnection(tuple);
        conn.close();

        // Closed connection should be cleaned up immediately
        int removed = tracker.cleanupStale(Duration.ofMinutes(5));
        assertThat(removed).isEqualTo(1);
        assertThat(tracker.getActiveCount()).isEqualTo(0);
    }
}
