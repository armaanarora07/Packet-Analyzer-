package packetanalyzer.dpi;

import java.util.Optional;

/**
 * Simplified QUIC Initial packet inspector.
 * Searches for embedded TLS Client Hello patterns inside QUIC initial frames.
 * Mirrors the C++ QUICSNIExtractor class in sni_extractor.cpp.
 */
public final class QuicSniExtractor {

    private QuicSniExtractor() {
        // Utility
    }

    /**
     * Checks if the packet starts with a QUIC Long Header Initial packet byte.
     */
    public static boolean isQuicInitial(byte[] payload, int offset, int length) {
        if (payload == null || length < 5 || offset + 5 > payload.length) {
            return false;
        }
        // Long header flag is the high-order bit (0x80)
        return (payload[offset] & 0x80) != 0;
    }

    /**
     * Attempts to find and extract SNI from within a QUIC Initial packet.
     */
    public static Optional<String> extract(byte[] payload, int offset, int length) {
        if (!isQuicInitial(payload, offset, length)) {
            return Optional.empty();
        }

        // Search for TLS Client Hello signature byte inside the QUIC packet
        int end = offset + length;
        for (int i = offset; i + 50 < end; i++) {
            if ((payload[i] & 0xFF) == 0x01) { // Client Hello handshake byte
                // Check if preceded by TLS record header (0x16)
                if (i >= 5 && (payload[i - 5] & 0xFF) == 0x16) {
                    Optional<String> sni = SniExtractor.extract(payload, i - 5, end - (i - 5));
                    if (sni.isPresent()) {
                        return sni;
                    }
                }
            }
        }

        return Optional.empty();
    }
}
