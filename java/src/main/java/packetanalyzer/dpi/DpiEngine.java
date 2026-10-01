package packetanalyzer.dpi;

import packetanalyzer.model.AppType;
import packetanalyzer.model.Connection;
import packetanalyzer.model.ConnectionState;
import packetanalyzer.model.FiveTuple;
import packetanalyzer.model.PacketAction;
import packetanalyzer.model.ParsedPacket;
import packetanalyzer.model.RawPacket;
import packetanalyzer.model.TcpHeader;
import packetanalyzer.parser.PacketParser;
import packetanalyzer.pcap.DefaultPcapReader;
import packetanalyzer.pcap.PcapReader;
import packetanalyzer.pcap.PcapWriter;
import packetanalyzer.rules.BlockReason;
import packetanalyzer.rules.RuleManager;
import packetanalyzer.stats.DpiStatistics;
import packetanalyzer.stats.DpiStatsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.Optional;

/**
 * Main DPI Engine orchestrating packet reading, layer parsing, flow tracking,
 * payload inspection (TLS SNI / HTTP Host / DNS), rule evaluation, and output generation.
 *
 * <p>Direct equivalent of the C++ {@code DPIEngine} class.</p>
 */
public class DpiEngine {

    private static final Logger logger = LoggerFactory.getLogger(DpiEngine.class);

    private final RuleManager ruleManager;
    private final ConnectionTracker connectionTracker;
    private final DpiStatistics statistics;
    private final DpiStatsService statsService;

    private int packetLimit = -1;
    private boolean verbose = false;

    public DpiEngine() {
        this.ruleManager = new RuleManager();
        this.connectionTracker = new ConnectionTracker();
        this.statistics = new DpiStatistics();
        this.statsService = new DpiStatsService(statistics, connectionTracker);
    }

    public DpiEngine(RuleManager ruleManager) {
        this.ruleManager = ruleManager != null ? ruleManager : new RuleManager();
        this.connectionTracker = new ConnectionTracker();
        this.statistics = new DpiStatistics();
        this.statsService = new DpiStatsService(statistics, connectionTracker);
    }

    public RuleManager getRuleManager() {
        return ruleManager;
    }

    public ConnectionTracker getConnectionTracker() {
        return connectionTracker;
    }

    public DpiStatistics getStatistics() {
        return statistics;
    }

    public DpiStatsService getStatsService() {
        return statsService;
    }

    public void setPacketLimit(int packetLimit) {
        this.packetLimit = packetLimit;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    /**
     * Processes an input PCAP file, filtering packets and writing forwarded packets to output.
     *
     * @param inputPath  Path to input .pcap file
     * @param outputPath Path to output .pcap file (or null if no output file requested)
     * @return {@code true} if completed successfully
     * @throws IOException On file I/O errors
     */
    public boolean processFile(String inputPath, String outputPath) throws IOException {
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            System.err.println("Error: Input PCAP file does not exist: " + inputPath);
            return false;
        }

        try (PcapReader reader = new DefaultPcapReader()) {
            reader.open(inputFile);

            PcapWriter writer = null;
            if (outputPath != null && !outputPath.trim().isEmpty()) {
                writer = new PcapWriter(new File(outputPath), null);
                if (reader.getGlobalHeader() != null) {
                    writer.writeGlobalHeader(reader.getGlobalHeader());
                }
            }

            try {
                process(reader, writer);
            } finally {
                if (writer != null) {
                    writer.close();
                }
            }
        }

        return true;
    }

    /**
     * Core processing loop consuming packets from a {@link PcapReader}.
     */
    public void process(PcapReader reader, PcapWriter writer) throws IOException {
        RawPacket raw;
        int packetIndex = 0;

        while ((raw = reader.readNextPacket()) != null) {
            packetIndex++;

            Optional<ParsedPacket> optParsed = PacketParser.parse(raw);
            if (optParsed.isEmpty()) {
                statistics.recordPacket(raw.getLength(), false, false);
                continue;
            }

            ParsedPacket parsed = optParsed.get();
            boolean isTcp = parsed.hasTcp();
            boolean isUdp = parsed.hasUdp();
            statistics.recordPacket(raw.getLength(), isTcp, isUdp);

            // DPI flow inspection requires IP and Transport headers
            if (!parsed.hasIp() || (!isTcp && !isUdp)) {
                // Forward non-IP or non-TCP/UDP packets (e.g. ARP, ICMP)
                statistics.recordForwarded();
                if (writer != null) {
                    writer.writePacket(raw);
                }
                if (packetLimit > 0 && packetIndex >= packetLimit) {
                    break;
                }
                continue;
            }

            FiveTuple tuple = parsed.getFiveTuple().orElse(null);
            if (tuple == null) {
                continue;
            }

            // 1. Connection / Flow Tracking
            Connection conn = connectionTracker.getOrCreateConnection(tuple);
            connectionTracker.updateConnection(conn, raw.getLength(), true);

            // Update TCP state flags if applicable
            if (isTcp && parsed.getTcpHeader().isPresent()) {
                updateTcpState(conn, parsed.getTcpHeader().get());
            }

            // 2. Deep Packet Inspection & Payload Extraction
            // If flow is not classified yet (or classified only as generic HTTPS/HTTP without SNI)
            if (parsed.getPayloadLength() > 0 &&
                (conn.getAppType() == AppType.UNKNOWN || conn.getAppType() == AppType.HTTPS || conn.getAppType() == AppType.HTTP) &&
                conn.getSni().isEmpty()) {
                inspectPayload(parsed, conn);
            }

            // Fallback port-based classification if payload didn't yield specific app
            if (conn.getAppType() == AppType.UNKNOWN) {
                if (parsed.getDestPort() == 443 || parsed.getSrcPort() == 443) {
                    conn.setAppType(AppType.HTTPS);
                } else if (parsed.getDestPort() == 80 || parsed.getSrcPort() == 80) {
                    conn.setAppType(AppType.HTTP);
                } else if (parsed.getDestPort() == 53 || parsed.getSrcPort() == 53) {
                    conn.setAppType(AppType.DNS);
                }
            }

            // 3. Rule Evaluation & Decision
            PacketAction action = PacketAction.FORWARD;

            if (conn.getState() == ConnectionState.BLOCKED) {
                action = PacketAction.DROP;
            } else {
                Optional<BlockReason> blockReason = ruleManager.shouldBlock(
                    parsed.getSrcIp(),
                    parsed.getDestPort(),
                    conn.getAppType(),
                    conn.getSni()
                );

                if (blockReason.isPresent()) {
                    conn.block();
                    action = PacketAction.DROP;
                    if (verbose) {
                        System.out.println(String.format(
                            "[BLOCKED] Packet #%d: %s -> %s (%s) Reason: %s",
                            packetIndex, parsed.getSrcIp(), parsed.getDestIp(),
                            conn.getAppType().getDisplayName(), blockReason.get()
                        ));
                    }
                }
            }

            // 4. Packet Disposition & Accounting
            if (action == PacketAction.DROP) {
                statistics.recordDropped();
            } else {
                statistics.recordForwarded();
                if (writer != null) {
                    writer.writePacket(raw);
                }
            }

            if (packetLimit > 0 && packetIndex >= packetLimit) {
                if (verbose) {
                    System.out.println("\n(Stopped after reaching packet limit of " + packetLimit + ")");
                }
                break;
            }
        }

        statistics.setActiveConnections(connectionTracker.getActiveCount());
    }

    /**
     * Inspects packet payload for TLS Client Hello SNI, HTTP Host, or DNS queries.
     */
    private void inspectPayload(ParsedPacket packet, Connection conn) {
        byte[] rawData = packet.getRawData();
        int offset = packet.getPayloadOffset();
        int length = packet.getPayloadLength();

        if (rawData == null || length <= 0 || offset >= rawData.length) {
            return;
        }

        // 1. Try TLS SNI extraction (Port 443 or matching TLS Client Hello record)
        if (packet.getDestPort() == 443 || SniExtractor.isTlsClientHello(rawData, offset, length)) {
            Optional<String> sniOpt = SniExtractor.extract(rawData, offset, length);
            if (sniOpt.isPresent()) {
                String sni = sniOpt.get();
                AppType app = ApplicationClassifier.classifyFromDomain(sni);
                connectionTracker.classifyConnection(conn, app, sni);
                return;
            }
        }

        // 2. Try HTTP Host header extraction (Port 80 or matching HTTP request)
        if (packet.getDestPort() == 80 || HttpHostExtractor.isHttpRequest(rawData, offset, length)) {
            Optional<String> hostOpt = HttpHostExtractor.extract(rawData, offset, length);
            if (hostOpt.isPresent()) {
                String host = hostOpt.get();
                AppType app = ApplicationClassifier.classifyFromDomain(host);
                connectionTracker.classifyConnection(conn, app, host);
                return;
            }
        }

        // 3. Try DNS Query domain extraction (Port 53)
        if (packet.getDestPort() == 53 || packet.getSrcPort() == 53) {
            Optional<String> dnsOpt = DnsExtractor.extractQuery(rawData, offset, length);
            if (dnsOpt.isPresent()) {
                connectionTracker.classifyConnection(conn, AppType.DNS, dnsOpt.get());
            }
        }
    }

    /**
     * Updates TCP connection lifecycle state from header flags.
     */
    private void updateTcpState(Connection conn, TcpHeader tcp) {
        if (tcp.isSyn()) {
            if (tcp.isAck()) {
                conn.setSynAckSeen(true);
            } else {
                conn.setSynSeen(true);
            }
        }

        if (conn.isSynSeen() && conn.isSynAckSeen() && tcp.isAck()) {
            if (conn.getState() == ConnectionState.NEW) {
                conn.setState(ConnectionState.ESTABLISHED);
            }
        }

        if (tcp.isFin()) {
            conn.setFinSeen(true);
        }

        if (tcp.isRst()) {
            conn.setState(ConnectionState.CLOSED);
        }

        if (conn.isFinSeen() && tcp.isAck()) {
            conn.setState(ConnectionState.CLOSED);
        }
    }
}
