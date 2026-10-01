package packetanalyzer.model;

/**
 * 24-byte PCAP file Global Header.
 * Stored at the beginning of every standard .pcap file.
 */
public record PcapGlobalHeader(
    long magicNumber,
    int versionMajor,
    int versionMinor,
    int thisZone,
    long sigFigs,
    long snapLen,
    long network // Link type: 1 = Ethernet
) {
    public static final long MAGIC_NATIVE = 0xa1b2c3d4L;
    public static final long MAGIC_SWAPPED = 0xd4c3b2a1L;
    public static final long LINKTYPE_ETHERNET = 1L;

    public boolean isEthernet() {
        return network == LINKTYPE_ETHERNET;
    }
}
