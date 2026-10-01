package packetanalyzer.parser;

import packetanalyzer.model.EthernetHeader;
import packetanalyzer.model.IPv4Header;
import packetanalyzer.model.ParsedPacket;
import packetanalyzer.model.RawPacket;
import packetanalyzer.model.TcpHeader;
import packetanalyzer.model.UdpHeader;
import packetanalyzer.util.NetworkUtils;

import java.util.Optional;

/**
 * Sequential protocol layer parser:
 * Ethernet (Layer 2) -&gt; IPv4 (Layer 3) -&gt; TCP/UDP (Layer 4) -&gt; Payload.
 *
 * <p>Direct equivalent of the C++ {@code PacketParser} class.</p>
 */
public final class PacketParser {

    private static final int ETH_HEADER_LEN = 14;
    private static final int MIN_IPV4_HEADER_LEN = 20;
    private static final int MIN_TCP_HEADER_LEN = 20;
    private static final int UDP_HEADER_LEN = 8;

    private PacketParser() {
        // Utility / parser class
    }

    /**
     * Parses a {@link RawPacket} into a structured {@link ParsedPacket}.
     *
     * @param raw Raw captured packet
     * @return {@link Optional} containing ParsedPacket if Ethernet layer was successfully decoded,
     *         or {@link Optional#empty()} if corrupted or truncated.
     */
    public static Optional<ParsedPacket> parse(RawPacket raw) {
        if (raw == null || raw.getData() == null || raw.getLength() < ETH_HEADER_LEN) {
            return Optional.empty();
        }

        byte[] data = raw.getData();
        int len = data.length;
        int offset = 0;

        // 1. Ethernet Header (14 bytes)
        byte[] destMacBytes = new byte[6];
        byte[] srcMacBytes = new byte[6];
        System.arraycopy(data, 0, destMacBytes, 0, 6);
        System.arraycopy(data, 6, srcMacBytes, 0, 6);

        String destMac = NetworkUtils.formatMac(destMacBytes);
        String srcMac = NetworkUtils.formatMac(srcMacBytes);
        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);

        EthernetHeader ethHeader = new EthernetHeader(srcMac, destMac, etherType);
        offset += ETH_HEADER_LEN;

        IPv4Header ipv4Header = null;
        TcpHeader tcpHeader = null;
        UdpHeader udpHeader = null;

        // 2. IPv4 Layer (if EtherType == 0x0800)
        if (etherType == EthernetHeader.ETHERTYPE_IPV4) {
            if (len >= offset + MIN_IPV4_HEADER_LEN) {
                int versionIhl = data[offset] & 0xFF;
                int version = (versionIhl >> 4) & 0x0F;
                int ihl = versionIhl & 0x0F;

                if (version == 4) {
                    int ipHeaderLen = ihl * 4;
                    if (ipHeaderLen >= MIN_IPV4_HEADER_LEN && len >= offset + ipHeaderLen) {
                        int tos = data[offset + 1] & 0xFF;
                        int totalLength = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                        int ident = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
                        int flagsFrag = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);
                        int flags = (flagsFrag >> 13) & 0x07;
                        int fragOffset = flagsFrag & 0x1FFF;
                        int ttl = data[offset + 8] & 0xFF;
                        int protocol = data[offset + 9] & 0xFF;
                        int checksum = ((data[offset + 10] & 0xFF) << 8) | (data[offset + 11] & 0xFF);

                        String srcIp = (data[offset + 12] & 0xFF) + "." +
                                       (data[offset + 13] & 0xFF) + "." +
                                       (data[offset + 14] & 0xFF) + "." +
                                       (data[offset + 15] & 0xFF);

                        String destIp = (data[offset + 16] & 0xFF) + "." +
                                        (data[offset + 17] & 0xFF) + "." +
                                        (data[offset + 18] & 0xFF) + "." +
                                        (data[offset + 19] & 0xFF);

                        ipv4Header = new IPv4Header(
                            version, ihl, tos, totalLength, ident,
                            flags, fragOffset, ttl, protocol, checksum,
                            srcIp, destIp
                        );

                        offset += ipHeaderLen;

                        // 3. Transport Layer
                        if (protocol == IPv4Header.PROTOCOL_TCP && len >= offset + MIN_TCP_HEADER_LEN) {
                            int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                            int destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                            long seq = (((long)(data[offset + 4] & 0xFF) << 24) |
                                        ((long)(data[offset + 5] & 0xFF) << 16) |
                                        ((long)(data[offset + 6] & 0xFF) << 8) |
                                        ((long)(data[offset + 7] & 0xFF))) & 0xFFFFFFFFL;
                            long ack = (((long)(data[offset + 8] & 0xFF) << 24) |
                                        ((long)(data[offset + 9] & 0xFF) << 16) |
                                        ((long)(data[offset + 10] & 0xFF) << 8) |
                                        ((long)(data[offset + 11] & 0xFF))) & 0xFFFFFFFFL;

                            int dataOffset = (data[offset + 12] >> 4) & 0x0F;
                            int tcpHeaderLen = dataOffset * 4;

                            if (tcpHeaderLen >= MIN_TCP_HEADER_LEN && len >= offset + tcpHeaderLen) {
                                int flagsTcp = data[offset + 13] & 0xFF;
                                int window = ((data[offset + 14] & 0xFF) << 8) | (data[offset + 15] & 0xFF);
                                int tcpChecksum = ((data[offset + 16] & 0xFF) << 8) | (data[offset + 17] & 0xFF);
                                int urgent = ((data[offset + 18] & 0xFF) << 8) | (data[offset + 19] & 0xFF);

                                tcpHeader = new TcpHeader(
                                    srcPort, destPort, seq, ack,
                                    dataOffset, flagsTcp, window, tcpChecksum, urgent
                                );

                                offset += tcpHeaderLen;
                            }
                        } else if (protocol == IPv4Header.PROTOCOL_UDP && len >= offset + UDP_HEADER_LEN) {
                            int srcPort = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                            int destPort = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
                            int udpLen = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
                            int udpChecksum = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);

                            udpHeader = new UdpHeader(srcPort, destPort, udpLen, udpChecksum);
                            offset += UDP_HEADER_LEN;
                        }
                    }
                }
            }
        }

        // 4. Payload Bounds
        int payloadOffset = offset;
        int payloadLength = Math.max(0, len - offset);

        return Optional.of(new ParsedPacket(
            raw.getTimestampSec(),
            raw.getTimestampUsec(),
            ethHeader,
            ipv4Header,
            tcpHeader,
            udpHeader,
            data,
            payloadOffset,
            payloadLength
        ));
    }
}
