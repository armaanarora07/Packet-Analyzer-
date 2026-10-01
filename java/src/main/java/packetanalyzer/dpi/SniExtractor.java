package packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Parses TLS Client Hello handshake packets to extract Server Name Indication (SNI).
 *
 * <p><b>Important Security Clarification:</b>
 * This component does NOT decrypt HTTPS traffic. TLS Client Hello is the first unencrypted message
 * sent by the client during TLS negotiation. In standard TLS (up to TLS 1.3 without ECH/ESNI),
 * the SNI extension containing the target hostname is transmitted in cleartext so that virtual-hosting
 * servers know which X.509 certificate to present.
 * </p>
 */
public final class SniExtractor {

    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private SniExtractor() {
        // Utility
    }

    /**
     * Checks if the given payload looks like a TLS Client Hello record.
     */
    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (payload == null || length < 9 || offset + length > payload.length) {
            return false;
        }

        // Byte 0: Content Type (0x16 = Handshake)
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) {
            return false;
        }

        // Bytes 1-2: Record TLS Version (0x0300 SSL 3.0 up to 0x0304 TLS 1.3)
        int version = ((payload[offset + 1] & 0xFF) << 8) | (payload[offset + 2] & 0xFF);
        if (version < 0x0300 || version > 0x0304) {
            return false;
        }

        // Bytes 3-4: Record Length
        int recordLength = ((payload[offset + 3] & 0xFF) << 8) | (payload[offset + 4] & 0xFF);
        if (recordLength > length - 5) {
            return false;
        }

        // Handshake Layer starts at byte 5
        // Byte 5: Handshake Type (0x01 = Client Hello)
        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    /**
     * Extracts the SNI hostname from a TLS Client Hello payload.
     *
     * @param payload Byte array containing TCP payload
     * @param offset  Offset into payload where TLS record begins
     * @param length  Available length of payload
     * @return Optional containing the extracted hostname string, or empty if absent / malformed
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) {
            return Optional.empty();
        }

        int curr = offset;
        int end = offset + length;

        // Skip TLS Record header (5 bytes: type, version, length)
        curr += 5;

        // Skip Handshake header (4 bytes: type, 24-bit length)
        curr += 4;

        // Client Version (2 bytes)
        curr += 2;

        // Random (32 bytes)
        curr += 32;

        // Session ID
        if (curr >= end) return Optional.empty();
        int sessionIdLen = payload[curr] & 0xFF;
        curr += 1 + sessionIdLen;

        // Cipher Suites
        if (curr + 2 > end) return Optional.empty();
        int cipherSuitesLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
        curr += 2 + cipherSuitesLen;

        // Compression Methods
        if (curr >= end) return Optional.empty();
        int compMethodsLen = payload[curr] & 0xFF;
        curr += 1 + compMethodsLen;

        // Extensions
        if (curr + 2 > end) return Optional.empty();
        int extensionsLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
        curr += 2;

        int extensionsEnd = Math.min(end, curr + extensionsLen);

        // Iterate through TLS Extensions
        while (curr + 4 <= extensionsEnd) {
            int extType = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
            int extLen = ((payload[curr + 2] & 0xFF) << 8) | (payload[curr + 3] & 0xFF);
            curr += 4;

            if (curr + extLen > extensionsEnd) {
                break; // Truncated extension
            }

            if (extType == EXTENSION_SNI) {
                // SNI structure:
                //   SNI List Length: 2 bytes
                //   SNI Type: 1 byte (0x00 = Hostname)
                //   SNI Length: 2 bytes
                //   SNI Hostname string: variable
                if (extLen < 5) break;

                int sniListLen = ((payload[curr] & 0xFF) << 8) | (payload[curr + 1] & 0xFF);
                if (sniListLen < 3) break;

                int sniType = payload[curr + 2] & 0xFF;
                int sniNameLen = ((payload[curr + 3] & 0xFF) << 8) | (payload[curr + 4] & 0xFF);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniNameLen > extLen - 5 || curr + 5 + sniNameLen > extensionsEnd) break;

                String hostname = new String(payload, curr + 5, sniNameLen, StandardCharsets.US_ASCII);
                return Optional.of(hostname);
            }

            curr += extLen;
        }

        return Optional.empty();
    }

    public static Optional<String> extract(byte[] payload) {
        if (payload == null) return Optional.empty();
        return extract(payload, 0, payload.length);
    }
}
