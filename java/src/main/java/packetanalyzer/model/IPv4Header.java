package packetanalyzer.model;

/**
 * Parsed IPv4 Layer 3 Header (typically 20-60 bytes).
 */
public record IPv4Header(
    int version,
    int ihl,
    int tos,
    int totalLength,
    int identification,
    int flags,
    int fragmentOffset,
    int ttl,
    int protocol,
    int checksum,
    String srcIp,
    String destIp
) {
    public static final int PROTOCOL_ICMP = 1;
    public static final int PROTOCOL_TCP = 6;
    public static final int PROTOCOL_UDP = 17;

    public int getHeaderLengthBytes() {
        return ihl * 4;
    }

    public boolean isTcp() {
        return protocol == PROTOCOL_TCP;
    }

    public boolean isUdp() {
        return protocol == PROTOCOL_UDP;
    }

    public boolean isIcmp() {
        return protocol == PROTOCOL_ICMP;
    }
}
