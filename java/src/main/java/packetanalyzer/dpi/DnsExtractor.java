package packetanalyzer.dpi;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Parses DNS query requests (UDP/TCP port 53) to extract the queried domain name.
 * Mirrors the C++ DNSExtractor class in sni_extractor.cpp.
 */
public final class DnsExtractor {

    private DnsExtractor() {
        // Utility
    }

    /**
     * Checks if the payload contains a valid DNS query header.
     */
    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (payload == null || length < 12 || offset + length > payload.length) {
            return false;
        }

        // Byte 2: Flags. QR bit (bit 7) must be 0 for standard query (1 is response)
        int flags = payload[offset + 2] & 0xFF;
        if ((flags & 0x80) != 0) {
            return false;
        }

        // Bytes 4-5: QDCOUNT (Question count) must be > 0
        int qdcount = ((payload[offset + 4] & 0xFF) << 8) | (payload[offset + 5] & 0xFF);
        return qdcount > 0;
    }

    /**
     * Extracts the primary queried domain name from the question section.
     */
    public static Optional<String> extractQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) {
            return Optional.empty();
        }

        int curr = offset + 12; // DNS question section begins after 12-byte header
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (curr < end) {
            int labelLen = payload[curr] & 0xFF;
            if (labelLen == 0) {
                // End of question domain name labels
                break;
            }

            if (labelLen > 63 || curr + 1 + labelLen > end) {
                // Invalid label length or compression pointer (DNS queries don't use pointers for QNAME)
                break;
            }

            curr++;
            if (domain.length() > 0) {
                domain.append('.');
            }
            domain.append(new String(payload, curr, labelLen, StandardCharsets.US_ASCII));
            curr += labelLen;
        }

        return domain.length() > 0 ? Optional.of(domain.toString()) : Optional.empty();
    }

    public static Optional<String> extractQuery(byte[] payload) {
        if (payload == null) return Optional.empty();
        return extractQuery(payload, 0, payload.length);
    }
}
