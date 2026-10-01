package packetanalyzer.model;

/**
 * 16-byte PCAP Packet Header preceding each recorded packet frame.
 */
public record PcapPacketHeader(
    long tsSec,   // Timestamp seconds
    long tsUsec,  // Timestamp microseconds
    int inclLen,  // Number of octets of packet saved in file
    int origLen   // Actual length of packet
) {
}
