package packetanalyzer.api;

import org.junit.jupiter.api.Test;
import packetanalyzer.dpi.ConnectionTracker;
import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.model.ConnectionState;
import packetanalyzer.model.FiveTuple;
import packetanalyzer.model.PacketAction;
import packetanalyzer.stats.DpiStatistics;
import packetanalyzer.stats.DpiStatsService;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JsonUtilsTest {

    @Test
    void testStatsToJsonWithValidData() {
        DpiStatistics stats = new DpiStatistics();
        ConnectionTracker tracker = new ConnectionTracker();
        DpiStatsService statsService = new DpiStatsService(stats, tracker);

        // Record some dummy packet data
        FiveTuple tuple1 = new FiveTuple("192.168.1.100", "142.250.190.46", 50000, 443, 6);
        Connection conn1 = tracker.getOrCreateConnection(tuple1);
        conn1.setAppType(AppType.YOUTUBE);
        conn1.setSni("youtube.com");
        conn1.update(1500, true);
        stats.recordPacket(1500, true, false);
        stats.recordForwarded();

        FiveTuple tuple2 = new FiveTuple("192.168.1.100", "8.8.8.8", 51000, 53, 17);
        Connection conn2 = tracker.getOrCreateConnection(tuple2);
        conn2.setAppType(AppType.DNS);
        conn2.update(80, false);
        stats.recordPacket(80, false, true);
        stats.recordForwarded();

        stats.recordPacket(200, true, false);
        stats.recordDropped();
        stats.setActiveConnections(2);

        String json = JsonUtils.statsToJson(statsService);

        assertThat(json).isNotNull();
        assertThat(json).contains("\"totalPackets\": 3");
        assertThat(json).contains("\"forwardedPackets\": 2");
        assertThat(json).contains("\"droppedPackets\": 1");
        assertThat(json).contains("\"tcpPackets\": 2");
        assertThat(json).contains("\"udpPackets\": 1");
        assertThat(json).contains("\"activeFlows\": 2");
        assertThat(json).contains("\"applicationDistribution\":");
        assertThat(json).contains("\"YouTube\": 1");
        assertThat(json).contains("\"DNS\": 1");
        assertThat(json).contains("\"topDomains\":");
        assertThat(json).contains("\"youtube.com\": 1");
        assertThat(json).contains("\"traffic\":");
    }

    @Test
    void testStatsToJsonNull() {
        assertThat(JsonUtils.statsToJson(null)).isEqualTo("{}");
    }

    @Test
    void testFlowsToJsonWithValidData() {
        FiveTuple tuple = new FiveTuple("10.0.0.1", "93.184.216.34", 45678, 443, 6);
        Connection conn = new Connection(tuple);
        conn.setAppType(AppType.HTTPS);
        conn.setSni("example.com");
        conn.setState(ConnectionState.ESTABLISHED);
        conn.setAction(PacketAction.FORWARD);
        conn.update(512, true);

        String json = JsonUtils.flowsToJson(List.of(conn));

        assertThat(json).isNotNull();
        assertThat(json).startsWith("[\n  {");
        assertThat(json).endsWith("}\n]");
        assertThat(json).contains("\"srcIp\": \"10.0.0.1\"");
        assertThat(json).contains("\"dstIp\": \"93.184.216.34\"");
        assertThat(json).contains("\"srcPort\": 45678");
        assertThat(json).contains("\"dstPort\": 443");
        assertThat(json).contains("\"protocol\": \"TCP\"");
        assertThat(json).contains("\"application\": \"HTTPS\"");
        assertThat(json).contains("\"sni\": \"example.com\"");
        assertThat(json).contains("\"packetCount\": 1");
        assertThat(json).contains("\"bytes\": 512");
        assertThat(json).contains("\"state\": \"ESTABLISHED\"");
        assertThat(json).contains("\"action\": \"FORWARD\"");
    }

    @Test
    void testFlowsToJsonEmptyAndNull() {
        assertThat(JsonUtils.flowsToJson(null)).isEqualTo("[]");
        assertThat(JsonUtils.flowsToJson(Collections.emptyList())).isEqualTo("[]");
    }

    @Test
    void testEscape() {
        assertThat(JsonUtils.escape(null)).isEqualTo("");
        assertThat(JsonUtils.escape("hello \"world\"")).isEqualTo("hello \\\"world\\\"");
        assertThat(JsonUtils.escape("path\\to\\file")).isEqualTo("path\\\\to\\\\file");
        assertThat(JsonUtils.escape("line1\nline2\ttab")).isEqualTo("line1\\nline2\\ttab");
    }
}
