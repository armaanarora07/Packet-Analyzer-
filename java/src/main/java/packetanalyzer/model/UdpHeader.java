package packetanalyzer.model;

/**
 * Parsed UDP Layer 4 Header (always fixed 8 bytes).
 */
public record UdpHeader(
    int srcPort,
    int destPort,
    int length,
    int checksum
) {
    public static final int HEADER_LENGTH_BYTES = 8;
}
