package packetanalyzer.model;

import java.util.Arrays;
import java.util.Optional;

/**
 * Encapsulates all parsed protocol layers of a single network frame:
 * Ethernet -&gt; IPv4 -&gt; TCP/UDP -&gt; Payload.
 */
public final class ParsedPacket {

    private final long timestampSec;
    private final long timestampUsec;
    private final EthernetHeader ethernetHeader;
    private final IPv4Header ipv4Header;
    private final TcpHeader tcpHeader;
    private final UdpHeader udpHeader;
    private final byte[] rawData;
    private final int payloadOffset;
    private final int payloadLength;

    public ParsedPacket(long timestampSec,
                        long timestampUsec,
                        EthernetHeader ethernetHeader,
                        IPv4Header ipv4Header,
                        TcpHeader tcpHeader,
                        UdpHeader udpHeader,
                        byte[] rawData,
                        int payloadOffset,
                        int payloadLength) {
        this.timestampSec = timestampSec;
        this.timestampUsec = timestampUsec;
        this.ethernetHeader = ethernetHeader;
        this.ipv4Header = ipv4Header;
        this.tcpHeader = tcpHeader;
        this.udpHeader = udpHeader;
        this.rawData = rawData;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
    }

    public long getTimestampSec() {
        return timestampSec;
    }

    public long getTimestampUsec() {
        return timestampUsec;
    }

    public EthernetHeader getEthernetHeader() {
        return ethernetHeader;
    }

    public Optional<IPv4Header> getIpv4Header() {
        return Optional.ofNullable(ipv4Header);
    }

    public Optional<TcpHeader> getTcpHeader() {
        return Optional.ofNullable(tcpHeader);
    }

    public Optional<UdpHeader> getUdpHeader() {
        return Optional.ofNullable(udpHeader);
    }

    public boolean hasIp() {
        return ipv4Header != null;
    }

    public boolean hasTcp() {
        return tcpHeader != null;
    }

    public boolean hasUdp() {
        return udpHeader != null;
    }

    public String getSrcIp() {
        return ipv4Header != null ? ipv4Header.srcIp() : "";
    }

    public String getDestIp() {
        return ipv4Header != null ? ipv4Header.destIp() : "";
    }

    public int getSrcPort() {
        if (tcpHeader != null) return tcpHeader.srcPort();
        if (udpHeader != null) return udpHeader.srcPort();
        return 0;
    }

    public int getDestPort() {
        if (tcpHeader != null) return tcpHeader.destPort();
        if (udpHeader != null) return udpHeader.destPort();
        return 0;
    }

    public int getProtocol() {
        return ipv4Header != null ? ipv4Header.protocol() : 0;
    }

    public int getPayloadOffset() {
        return payloadOffset;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public byte[] getRawData() {
        return rawData;
    }

    /**
     * Extracts a fresh byte array containing only the payload bytes.
     */
    public byte[] getPayloadBytes() {
        if (payloadLength <= 0 || rawData == null || payloadOffset >= rawData.length) {
            return new byte[0];
        }
        int available = Math.min(payloadLength, rawData.length - payloadOffset);
        return Arrays.copyOfRange(rawData, payloadOffset, payloadOffset + available);
    }

    /**
     * Builds the FiveTuple flow identifier if IP and transport layers are present.
     */
    public Optional<FiveTuple> getFiveTuple() {
        if (hasIp() && (hasTcp() || hasUdp())) {
            return Optional.of(new FiveTuple(
                getSrcIp(),
                getDestIp(),
                getSrcPort(),
                getDestPort(),
                getProtocol()
            ));
        }
        return Optional.empty();
    }
}
