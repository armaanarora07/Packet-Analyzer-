package packetanalyzer;

import packetanalyzer.dpi.DnsExtractor;
import packetanalyzer.dpi.HttpHostExtractor;
import packetanalyzer.dpi.SniExtractor;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PayloadExtractorsTest {

    @Test
    void testSniExtractorWithValidClientHello() throws IOException {
        String expectedHostname = "www.youtube.com";
        byte[] tlsPacket = createTlsClientHello(expectedHostname);

        assertThat(SniExtractor.isTlsClientHello(tlsPacket, 0, tlsPacket.length)).isTrue();

        Optional<String> extractedSni = SniExtractor.extract(tlsPacket);
        assertThat(extractedSni).isPresent().contains(expectedHostname);
    }

    @Test
    void testSniExtractorRejectsNonTls() {
        byte[] garbage = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        assertThat(SniExtractor.isTlsClientHello(garbage, 0, garbage.length)).isFalse();
        assertThat(SniExtractor.extract(garbage)).isEmpty();
    }

    @Test
    void testHttpHostExtractor() {
        String httpRequest =
            "GET /index.html HTTP/1.1\r\n" +
            "Host: www.netflix.com:8080\r\n" +
            "User-Agent: Mozilla/5.0\r\n" +
            "Accept: */*\r\n\r\n";

        byte[] payload = httpRequest.getBytes(StandardCharsets.US_ASCII);
        assertThat(HttpHostExtractor.isHttpRequest(payload, 0, payload.length)).isTrue();

        Optional<String> host = HttpHostExtractor.extract(payload);
        assertThat(host).isPresent().contains("www.netflix.com");
    }

    @Test
    void testHttpHostExtractorRejectsNonHttp() {
        byte[] payload = "SOME_RANDOM_BINARY_DATA".getBytes(StandardCharsets.US_ASCII);
        assertThat(HttpHostExtractor.isHttpRequest(payload, 0, payload.length)).isFalse();
        assertThat(HttpHostExtractor.extract(payload)).isEmpty();
    }

    @Test
    void testDnsExtractor() {
        // Construct a DNS query for "api.github.com"
        // 12 bytes DNS header (ID=0x1234, QR=0 query, QDCOUNT=1)
        byte[] dnsHeader = new byte[] {
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (Standard query, QR=0)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00  // ARCOUNT = 0
        };

        // Question: 3api 6github 3com 0
        byte[] question = new byte[] {
            3, 'a', 'p', 'i',
            6, 'g', 'i', 't', 'h', 'u', 'b',
            3, 'c', 'o', 'm',
            0,          // End label
            0x00, 0x01, // QTYPE A
            0x00, 0x01  // QCLASS IN
        };

        byte[] dnsPacket = new byte[dnsHeader.length + question.length];
        System.arraycopy(dnsHeader, 0, dnsPacket, 0, dnsHeader.length);
        System.arraycopy(question, 0, dnsPacket, dnsHeader.length, question.length);

        assertThat(DnsExtractor.isDnsQuery(dnsPacket, 0, dnsPacket.length)).isTrue();
        Optional<String> domain = DnsExtractor.extractQuery(dnsPacket);
        assertThat(domain).isPresent().contains("api.github.com");
    }

    private byte[] createTlsClientHello(String sni) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        // 1. SNI Extension data
        byte[] sniBytes = sni.getBytes(StandardCharsets.US_ASCII);
        ByteArrayOutputStream sniExtBody = new ByteArrayOutputStream();
        int sniListLen = 1 + 2 + sniBytes.length; // type(1) + len(2) + val
        sniExtBody.write((sniListLen >> 8) & 0xFF);
        sniExtBody.write(sniListLen & 0xFF);
        sniExtBody.write(0); // SNI Type: 0 = Hostname
        sniExtBody.write((sniBytes.length >> 8) & 0xFF);
        sniExtBody.write(sniBytes.length & 0xFF);
        sniExtBody.write(sniBytes);

        byte[] sniExtData = sniExtBody.toByteArray();

        // Extensions block
        ByteArrayOutputStream extsBlock = new ByteArrayOutputStream();
        // Extension header: Type=0x0000, Length
        extsBlock.write(0x00);
        extsBlock.write(0x00);
        extsBlock.write((sniExtData.length >> 8) & 0xFF);
        extsBlock.write(sniExtData.length & 0xFF);
        extsBlock.write(sniExtData);

        byte[] allExts = extsBlock.toByteArray();

        // 2. Client Hello Handshake Body
        ByteArrayOutputStream handshakeBody = new ByteArrayOutputStream();
        handshakeBody.write(0x03);
        handshakeBody.write(0x03); // TLS 1.2 client version
        handshakeBody.write(new byte[32]); // 32 random bytes
        handshakeBody.write(0); // Session ID len = 0
        // Cipher suites
        handshakeBody.write(0x00);
        handshakeBody.write(0x02);
        handshakeBody.write(0x13);
        handshakeBody.write(0x01);
        // Compression methods
        handshakeBody.write(0x01);
        handshakeBody.write(0x00);
        // Extensions length + extensions
        handshakeBody.write((allExts.length >> 8) & 0xFF);
        handshakeBody.write(allExts.length & 0xFF);
        handshakeBody.write(allExts);

        byte[] handshakeData = handshakeBody.toByteArray();

        // 3. Handshake Header (Type 0x01 Client Hello, 24-bit length)
        ByteArrayOutputStream handshake = new ByteArrayOutputStream();
        handshake.write(0x01); // Client Hello
        handshake.write((handshakeData.length >> 16) & 0xFF);
        handshake.write((handshakeData.length >> 8) & 0xFF);
        handshake.write(handshakeData.length & 0xFF);
        handshake.write(handshakeData);

        byte[] fullHandshake = handshake.toByteArray();

        // 4. TLS Record Layer (0x16 Handshake, version 0x0301, length)
        out.write(0x16);
        out.write(0x03);
        out.write(0x01);
        out.write((fullHandshake.length >> 8) & 0xFF);
        out.write(fullHandshake.length & 0xFF);
        out.write(fullHandshake);

        return out.toByteArray();
    }
}
