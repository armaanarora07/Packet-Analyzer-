package packetanalyzer.api;

import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.stats.DpiStatistics;
import packetanalyzer.stats.DpiStatsService;
import packetanalyzer.util.NetworkUtils;

import java.util.List;
import java.util.Map;

/**
 * Lightweight, zero-dependency JSON serialization utility.
 * Formats DPI statistics and connection flows into clean JSON.
 */
public final class JsonUtils {

    private JsonUtils() {
        // Utility
    }

    /**
     * Serializes overall DPI statistics and application breakdown to JSON.
     */
    public static String statsToJson(DpiStatsService statsService) {
        if (statsService == null) {
            return "{}";
        }

        DpiStatistics stats = statsService.getStatistics();
        Map<AppType, Long> appDist = statsService.getApplicationDistribution();
        Map<String, Long> domainDist = statsService.getDomainDistribution();

        StringBuilder sb = new StringBuilder(1024);
        sb.append("{\n");
        sb.append("  \"totalPackets\": ").append(stats.getTotalPackets()).append(",\n");
        sb.append("  \"totalBytes\": ").append(stats.getTotalBytes()).append(",\n");
        sb.append("  \"forwardedPackets\": ").append(stats.getForwardedPackets()).append(",\n");
        sb.append("  \"droppedPackets\": ").append(stats.getDroppedPackets()).append(",\n");
        sb.append("  \"dropRatePercent\": ").append(String.format(java.util.Locale.US, "%.2f", stats.getDropRate())).append(",\n");
        sb.append("  \"tcpPackets\": ").append(stats.getTcpPackets()).append(",\n");
        sb.append("  \"udpPackets\": ").append(stats.getUdpPackets()).append(",\n");
        sb.append("  \"otherPackets\": ").append(stats.getOtherPackets()).append(",\n");
        sb.append("  \"activeFlows\": ").append(stats.getActiveConnections()).append(",\n");

        // Application distribution
        sb.append("  \"applicationDistribution\": {\n");
        int appCount = 0;
        for (Map.Entry<AppType, Long> entry : appDist.entrySet()) {
            if (appCount > 0) sb.append(",\n");
            sb.append("    \"").append(escape(entry.getKey().getDisplayName())).append("\": ").append(entry.getValue());
            appCount++;
        }
        sb.append("\n  },\n");

        // Top domains
        sb.append("  \"topDomains\": {\n");
        int domCount = 0;
        for (Map.Entry<String, Long> entry : domainDist.entrySet()) {
            if (domCount > 0) sb.append(",\n");
            sb.append("    \"").append(escape(entry.getKey())).append("\": ").append(entry.getValue());
            domCount++;
        }
        sb.append("\n  },\n");

        // Traffic summary
        sb.append("  \"traffic\": {\n");
        sb.append("    \"forwardedBytes\": ").append(stats.getTotalBytes()).append(",\n"); // outbound observed
        sb.append("    \"blockedTraffic\": ").append(stats.getDroppedPackets()).append(",\n");
        sb.append("    \"dropRate\": ").append(String.format(java.util.Locale.US, "%.2f", stats.getDropRate())).append("\n");
        sb.append("  }\n");
        sb.append("}");

        return sb.toString();
    }

    /**
     * Serializes currently tracked network flows to a JSON array.
     */
    public static String flowsToJson(List<Connection> connections) {
        if (connections == null || connections.isEmpty()) {
            return "[]";
        }

        StringBuilder sb = new StringBuilder(connections.size() * 256);
        sb.append("[\n");

        for (int i = 0; i < connections.size(); i++) {
            Connection conn = connections.get(i);
            if (i > 0) sb.append(",\n");

            sb.append("  {\n");
            sb.append("    \"srcIp\": \"").append(escape(conn.getTuple().getSrcIp())).append("\",\n");
            sb.append("    \"dstIp\": \"").append(escape(conn.getTuple().getDstIp())).append("\",\n");
            sb.append("    \"srcPort\": ").append(conn.getTuple().getSrcPort()).append(",\n");
            sb.append("    \"dstPort\": ").append(conn.getTuple().getDstPort()).append(",\n");
            sb.append("    \"protocol\": \"").append(escape(NetworkUtils.protocolToString(conn.getTuple().getProtocol()))).append("\",\n");
            sb.append("    \"application\": \"").append(escape(conn.getAppType().getDisplayName())).append("\",\n");
            sb.append("    \"sni\": \"").append(escape(conn.getSni())).append("\",\n");
            sb.append("    \"packetCount\": ").append(conn.getTotalPackets()).append(",\n");
            sb.append("    \"bytes\": ").append(conn.getTotalBytes()).append(",\n");
            sb.append("    \"state\": \"").append(conn.getState().name()).append("\",\n");
            sb.append("    \"action\": \"").append(conn.getAction().name()).append("\"\n");
            sb.append("  }");
        }

        sb.append("\n]");
        return sb.toString();
    }

    /**
     * Escapes special characters for JSON string output.
     */
    public static String escape(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
