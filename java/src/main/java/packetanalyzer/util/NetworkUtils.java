package packetanalyzer.util;

import java.util.StringJoiner;

/**
 * Portable networking utility methods for byte manipulations,
 * address formatting, and protocol name conversions.
 */
public final class NetworkUtils {

    private NetworkUtils() {
        // Utility class
    }

    /**
     * Converts a 6-byte array into a standard MAC address string (e.g. 00:1a:2b:3c:4d:5e).
     */
    public static String formatMac(byte[] mac) {
        if (mac == null || mac.length < 6) {
            return "00:00:00:00:00:00";
        }
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", mac[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Converts an IPv4 address in network byte order (big-endian 32-bit int)
     * to a dotted decimal string (e.g. 192.168.1.1).
     */
    public static String formatIpv4(int ip) {
        return ((ip >> 24) & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 8) & 0xFF) + "." +
               (ip & 0xFF);
    }

    /**
     * Parses a dotted decimal IPv4 string (e.g. "192.168.1.1") into a 32-bit integer (big-endian).
     */
    public static int parseIpv4(String ipStr) {
        if (ipStr == null || ipStr.trim().isEmpty()) {
            return 0;
        }
        String[] parts = ipStr.trim().split("\\.");
        if (parts.length != 4) {
            return 0;
        }
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(parts[i]);
            result = (result << 8) | (octet & 0xFF);
        }
        return result;
    }

    /**
     * Converts dotted decimal IPv4 string to an unsigned 32-bit value in a long.
     */
    public static long parseIpv4ToLong(String ipStr) {
        return Integer.toUnsignedLong(parseIpv4(ipStr));
    }

    /**
     * Converts protocol number to human-readable protocol string.
     */
    public static String protocolToString(int protocol) {
        return switch (protocol) {
            case 1 -> "ICMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            default -> "Unknown(" + protocol + ")";
        };
    }

    /**
     * Converts TCP flags byte into space-separated string (e.g. "SYN ACK").
     */
    public static String tcpFlagsToString(int flags) {
        StringJoiner sj = new StringJoiner(" ");
        if ((flags & 0x02) != 0) sj.add("SYN");
        if ((flags & 0x10) != 0) sj.add("ACK");
        if ((flags & 0x01) != 0) sj.add("FIN");
        if ((flags & 0x04) != 0) sj.add("RST");
        if ((flags & 0x08) != 0) sj.add("PSH");
        if ((flags & 0x20) != 0) sj.add("URG");
        return sj.length() == 0 ? "none" : sj.toString();
    }

    /**
     * Formats bytes as a hex preview string (e.g. "16 03 01 00 ...").
     */
    public static String bytesToHex(byte[] bytes, int offset, int length, int maxBytes) {
        if (bytes == null || length <= 0 || offset >= bytes.length) {
            return "";
        }
        int count = Math.min(length, Math.min(maxBytes, bytes.length - offset));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", bytes[offset + i] & 0xFF));
        }
        if (length > maxBytes) {
            sb.append(" ...");
        }
        return sb.toString();
    }
}
