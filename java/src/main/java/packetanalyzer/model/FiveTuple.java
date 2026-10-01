package packetanalyzer.model;

import packetanalyzer.util.NetworkUtils;
import java.util.Objects;

/**
 * An immutable representation of a network flow identifier (Five-Tuple):
 * Source IP, Destination IP, Source Port, Destination Port, and Protocol.
 *
 * <p><b>Why Immutability and Correct Equality/HashCode are Critical for Flow Tracking:</b></p>
 * <ul>
 *   <li><b>HashMap / HashSet Key Stability:</b> In network packet inspection and flow tracking,
 *       the FiveTuple is used as the primary lookup key in flow tables (e.g. {@code Map<FiveTuple, Connection>}).
 *       Java HashMaps locate buckets based on {@code key.hashCode()}. If a key object were mutable and
 *       its state modified after insertion, its hashCode would change, causing the entry to "disappear"
 *       from map lookups. This would produce corrupted connection state, duplicate flows, and severe memory leaks.</li>
 *   <li><b>Bidirectional Flow Affinity:</b> Packets flowing from Client -&gt; Server and Server -&gt; Client
 *       belong to the same logical conversation. Correct value-based {@code equals()} and {@code hashCode()}
 *       combined with the {@link #reverse()} method allow fast, reliable correlation of both directions of a session.</li>
 *   <li><b>Thread-Safety:</b> Immutable objects are inherently thread-safe without requiring synchronization
 *       locks when shared or queried across threads or pipeline stages.</li>
 * </ul>
 */
public final class FiveTuple {

    private final String srcIp;
    private final String dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol; // TCP=6, UDP=17, ICMP=1

    // Precomputed hash code for fast Map lookup performance
    private final int cachedHashCode;

    /**
     * Constructs an immutable FiveTuple.
     *
     * @param srcIp    Source IPv4 dotted string (e.g. "192.168.1.100")
     * @param dstIp    Destination IPv4 dotted string (e.g. "142.250.190.46")
     * @param srcPort  Source port (0-65535)
     * @param dstPort  Destination port (0-65535)
     * @param protocol IP protocol number (e.g. 6 for TCP, 17 for UDP)
     */
    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = Objects.requireNonNull(srcIp, "srcIp cannot be null").trim();
        this.dstIp = Objects.requireNonNull(dstIp, "dstIp cannot be null").trim();
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;

        // Compute hash code once during construction (effective 31-multiplier combination)
        int h = 17;
        h = 31 * h + this.srcIp.hashCode();
        h = 31 * h + this.dstIp.hashCode();
        h = 31 * h + Integer.hashCode(this.srcPort);
        h = 31 * h + Integer.hashCode(this.dstPort);
        h = 31 * h + Integer.hashCode(this.protocol);
        this.cachedHashCode = h;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    /**
     * Creates a reversed tuple with swapped source/destination addresses and ports.
     * Used for correlating bidirectional traffic in connection tracking.
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple that = (FiveTuple) o;
        return srcPort == that.srcPort &&
               dstPort == that.dstPort &&
               protocol == that.protocol &&
               srcIp.equals(that.srcIp) &&
               dstIp.equals(that.dstIp);
    }

    @Override
    public int hashCode() {
        return cachedHashCode;
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort +
               " (" + NetworkUtils.protocolToString(protocol) + ")";
    }
}
