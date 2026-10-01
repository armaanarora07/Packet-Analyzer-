package packetanalyzer;

import packetanalyzer.model.PcapPacketHeader;
import packetanalyzer.model.ParsedPacket;
import packetanalyzer.model.RawPacket;
import packetanalyzer.parser.PacketParser;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PacketParserTest {

    @Test
    void testParseValidTcpPacket() throws IOException {
        byte[] frame = createSyntheticTcpPacket(
            "00:11:22:33:44:55", "66:77:88:99:aa:bb",
            "192.168.1.10", "142.250.190.46",
            50000, 443,
            0x02, // SYN
            "Hello TLS".getBytes()
        );

        PcapPacketHeader header = new PcapPacketHeader(1700000000L, 123456L, frame.length, frame.length);
        RawPacket raw = new RawPacket(header, frame);

        Optional<ParsedPacket> optParsed = PacketParser.parse(raw);
        assertThat(optParsed).isPresent();

        ParsedPacket parsed = optParsed.get();
        assertThat(parsed.getEthernetHeader().srcMac()).isEqualTo("00:11:22:33:44:55");
        assertThat(parsed.getEthernetHeader().destMac()).isEqualTo("66:77:88:99:aa:bb");
        assertThat(parsed.hasIp()).isTrue();
        assertThat(parsed.getSrcIp()).isEqualTo("192.168.1.10");
        assertThat(parsed.getDestIp()).isEqualTo("142.250.190.46");
        assertThat(parsed.getProtocol()).isEqualTo(6); // TCP
        assertThat(parsed.hasTcp()).isTrue();
        assertThat(parsed.getSrcPort()).isEqualTo(50000);
        assertThat(parsed.getDestPort()).isEqualTo(443);
        assertThat(parsed.getTcpHeader().get().isSyn()).isTrue();
        assertThat(parsed.getPayloadLength()).isEqualTo("Hello TLS".getBytes().length);
    }

    @Test
    void testParseValidUdpPacket() throws IOException {
        byte[] frame = createSyntheticUdpPacket(
            "192.168.1.100", "8.8.8.8",
            5353, 53,
            new byte[]{0, 1, 2, 3}
        );

        PcapPacketHeader header = new PcapPacketHeader(1700000000L, 0, frame.length, frame.length);
        RawPacket raw = new RawPacket(header, frame);

        Optional<ParsedPacket> optParsed = PacketParser.parse(raw);
        assertThat(optParsed).isPresent();

        ParsedPacket parsed = optParsed.get();
        assertThat(parsed.hasIp()).isTrue();
        assertThat(parsed.hasUdp()).isTrue();
        assertThat(parsed.getSrcPort()).isEqualTo(5353);
        assertThat(parsed.getDestPort()).isEqualTo(53);
        assertThat(parsed.getProtocol()).isEqualTo(17);
        assertThat(parsed.getPayloadLength()).isEqualTo(4);
    }

    @Test
    void testMalformedTruncatedPacket() {
        // Less than 14 bytes (Ethernet header length)
        byte[] tiny = new byte[]{1, 2, 3};
        RawPacket raw = new RawPacket(new PcapPacketHeader(0, 0, tiny.length, tiny.length), tiny);
        assertThat(PacketParser.parse(raw)).isEmpty();
    }

    private byte[] createSyntheticTcpPacket(String srcMac, String dstMac,
                                           String srcIp, String dstIp,
                                           int srcPort, int dstPort,
                                           int flags, byte[] payload) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 1. Ethernet (14 bytes)
        out.write(parseMacBytes(dstMac));
        out.write(parseMacBytes(srcMac));
        out.write(0x08); // IPv4 (0x0800)
        out.write(0x00);

        // 2. IPv4 (20 bytes)
        int totalLen = 20 + 20 + payload.length;
        out.write(0x45); // version 4, IHL 5 (20 bytes)
        out.write(0x00); // TOS
        out.write((totalLen >> 8) & 0xFF);
        out.write(totalLen & 0xFF);
        out.write(0x12); // Ident
        out.write(0x34);
        out.write(0x40); // Flags (DF)
        out.write(0x00);
        out.write(64);   // TTL
        out.write(6);    // TCP
        out.write(0);    // Checksum
        out.write(0);
        out.write(parseIpBytes(srcIp));
        out.write(parseIpBytes(dstIp));

        // 3. TCP (20 bytes)
        out.write((srcPort >> 8) & 0xFF);
        out.write(srcPort & 0xFF);
        out.write((dstPort >> 8) & 0xFF);
        out.write(dstPort & 0xFF);
        out.write(ByteBuffer.allocate(4).putInt(1001).array()); // Seq
        out.write(ByteBuffer.allocate(4).putInt(0).array());    // Ack
        out.write((5 << 4)); // Data offset = 5 words (20 bytes)
        out.write(flags);    // Flags
        out.write(0xFF);     // Window
        out.write(0xFF);
        out.write(0);        // Checksum
        out.write(0);
        out.write(0);        // Urgent
        out.write(0);

        // 4. Payload
        out.write(payload);

        return out.toByteArray();
    }

    private byte[] createSyntheticUdpPacket(String srcIp, String dstIp,
                                           int srcPort, int dstPort,
                                           byte[] payload) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // Ethernet
        out.write(new byte[]{0, 0, 0, 0, 0, 1});
        out.write(new byte[]{0, 0, 0, 0, 0, 2});
        out.write(0x08);
        out.write(0x00);

        // IPv4
        int totalLen = 20 + 8 + payload.length;
        out.write(0x45);
        out.write(0);
        out.write((totalLen >> 8) & 0xFF);
        out.write(totalLen & 0xFF);
        out.write(0);
        out.write(1);
        out.write(0);
        out.write(0);
        out.write(64);
        out.write(17); // UDP
        out.write(0);
        out.write(0);
        out.write(parseIpBytes(srcIp));
        out.write(parseIpBytes(dstIp));

        // UDP (8 bytes)
        out.write((srcPort >> 8) & 0xFF);
        out.write(srcPort & 0xFF);
        out.write((dstPort >> 8) & 0xFF);
        out.write(dstPort & 0xFF);
        int udpLen = 8 + payload.length;
        out.write((udpLen >> 8) & 0xFF);
        out.write(udpLen & 0xFF);
        out.write(0);
        out.write(0);

        // Payload
        out.write(payload);

        return out.toByteArray();
    }

    private byte[] parseMacBytes(String mac) {
        String[] parts = mac.split(":");
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i], 16);
        }
        return bytes;
    }

    private byte[] parseIpBytes(String ip) {
        String[] parts = ip.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }
}
