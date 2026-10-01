package packetanalyzer.model;

/**
 * Parsed Ethernet Layer 2 Header (14 bytes).
 */
public record EthernetHeader(
    String srcMac,
    String destMac,
    int etherType // e.g. 0x0800 for IPv4, 0x86DD for IPv6, 0x0806 for ARP
) {
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_ARP = 0x0806;

    public boolean isIPv4() {
        return etherType == ETHERTYPE_IPV4;
    }

    public boolean isIPv6() {
        return etherType == ETHERTYPE_IPV6;
    }

    public boolean isArp() {
        return etherType == ETHERTYPE_ARP;
    }
}
