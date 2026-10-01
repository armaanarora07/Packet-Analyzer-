package packetanalyzer.model;

import packetanalyzer.util.NetworkUtils;

/**
 * Parsed TCP Layer 4 Header (20-60 bytes).
 */
public record TcpHeader(
    int srcPort,
    int destPort,
    long seqNumber,
    long ackNumber,
    int dataOffset,
    int flags,
    int window,
    int checksum,
    int urgentPointer
) {
    public static final int FLAG_FIN = 0x01;
    public static final int FLAG_SYN = 0x02;
    public static final int FLAG_RST = 0x04;
    public static final int FLAG_PSH = 0x08;
    public static final int FLAG_ACK = 0x10;
    public static final int FLAG_URG = 0x20;

    public int getHeaderLengthBytes() {
        return dataOffset * 4;
    }

    public boolean isSyn() {
        return (flags & FLAG_SYN) != 0;
    }

    public boolean isAck() {
        return (flags & FLAG_ACK) != 0;
    }

    public boolean isFin() {
        return (flags & FLAG_FIN) != 0;
    }

    public boolean isRst() {
        return (flags & FLAG_RST) != 0;
    }

    public boolean isPsh() {
        return (flags & FLAG_PSH) != 0;
    }

    public boolean isUrg() {
        return (flags & FLAG_URG) != 0;
    }

    public String getFlagsString() {
        return NetworkUtils.tcpFlagsToString(flags);
    }
}
