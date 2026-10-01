package packetanalyzer.stats;

import packetanalyzer.dpi.ConnectionTracker;
import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service exposing statistics, application breakdown, and reporting.
 *
 * <p>Architectural preparation for future REST API and HTML/JS Dashboard:
 * Exposes clean POJO getters and data structures so a lightweight REST controller
 * can serialize this service's outputs directly to JSON without modifying the core DPI engine.</p>
 */
public class DpiStatsService {

    private final DpiStatistics statistics;
    private final ConnectionTracker connectionTracker;

    public DpiStatsService(DpiStatistics statistics, ConnectionTracker connectionTracker) {
        this.statistics = statistics;
        this.connectionTracker = connectionTracker;
    }

    public DpiStatistics getStatistics() {
        return statistics.snapshot();
    }

    public Map<AppType, Long> getApplicationDistribution() {
        Map<AppType, Long> distribution = new EnumMap<>(AppType.class);
        if (connectionTracker != null) {
            connectionTracker.forEach(conn -> {
                distribution.merge(conn.getAppType(), 1L, Long::sum);
            });
        }
        return distribution;
    }

    public Map<String, Long> getDomainDistribution() {
        Map<String, Long> domains = new HashMap<>();
        if (connectionTracker != null) {
            connectionTracker.forEach(conn -> {
                String sni = conn.getSni();
                if (sni != null && !sni.trim().isEmpty()) {
                    domains.merge(sni.trim(), 1L, Long::sum);
                }
            });
        }
        return domains;
    }

    public List<Connection> getActiveConnections() {
        return connectionTracker != null ? connectionTracker.getAllConnections() : Collections.emptyList();
    }

    /**
     * Generates a formatted ASCII processing report matching the C++ DPI engine output.
     */
    public String generateSummaryReport() {
        DpiStatistics stats = getStatistics();
        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                    DPI ENGINE STATISTICS                      ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ PACKET STATISTICS                                             ║\n"));
        sb.append(String.format("║   Total Packets:      %12d                        ║\n", stats.getTotalPackets()));
        sb.append(String.format("║   Total Bytes:        %12d                        ║\n", stats.getTotalBytes()));
        sb.append(String.format("║   TCP Packets:        %12d                        ║\n", stats.getTcpPackets()));
        sb.append(String.format("║   UDP Packets:        %12d                        ║\n", stats.getUdpPackets()));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ FILTERING STATISTICS                                          ║\n"));
        sb.append(String.format("║   Forwarded:          %12d                        ║\n", stats.getForwardedPackets()));
        sb.append(String.format("║   Dropped/Blocked:    %12d                        ║\n", stats.getDroppedPackets()));
        sb.append(String.format("║   Drop Rate:          %11.2f%%                        ║\n", stats.getDropRate()));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ FLOW STATISTICS                                               ║\n"));
        sb.append(String.format("║   Active Flows:       %12d                        ║\n",
            connectionTracker != null ? connectionTracker.getActiveCount() : 0));
        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }

    /**
     * Generates a formatted ASCII application classification breakdown.
     */
    public String generateClassificationReport() {
        Map<AppType, Long> appCounts = getApplicationDistribution();
        long totalFlows = appCounts.values().stream().mapToLong(Long::longValue).sum();

        long totalClassified = 0;
        long totalUnknown = 0;

        for (Map.Entry<AppType, Long> e : appCounts.entrySet()) {
            if (e.getKey() == AppType.UNKNOWN) {
                totalUnknown += e.getValue();
            } else {
                totalClassified += e.getValue();
            }
        }

        double classifiedPct = totalFlows > 0 ? (100.0 * totalClassified / totalFlows) : 0;
        double unknownPct = totalFlows > 0 ? (100.0 * totalUnknown / totalFlows) : 0;

        StringBuilder sb = new StringBuilder();
        sb.append("\n╔══════════════════════════════════════════════════════════════╗\n");
        sb.append("║                 APPLICATION CLASSIFICATION REPORT             ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append(String.format("║ Total Flows:          %10d                             ║\n", totalFlows));
        sb.append(String.format("║ Classified:           %10d (%5.1f%%)                   ║\n", totalClassified, classifiedPct));
        sb.append(String.format("║ Unidentified:         %10d (%5.1f%%)                   ║\n", totalUnknown, unknownPct));
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");
        sb.append("║                    APPLICATION DISTRIBUTION                   ║\n");
        sb.append("╠══════════════════════════════════════════════════════════════╣\n");

        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appCounts.entrySet());
        sortedApps.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            double pct = totalFlows > 0 ? (100.0 * entry.getValue() / totalFlows) : 0;
            int barLen = (int) (pct / 5.0);
            String bar = "#".repeat(Math.max(0, Math.min(20, barLen)));
            sb.append(String.format("║ %-16s %8d %5.1f%%  %-20s ║\n",
                entry.getKey().getDisplayName(), entry.getValue(), pct, bar));
        }

        sb.append("╚══════════════════════════════════════════════════════════════╝\n");
        return sb.toString();
    }
}
