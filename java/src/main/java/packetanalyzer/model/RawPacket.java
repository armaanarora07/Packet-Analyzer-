package packetanalyzer.model;

import java.util.Arrays;
import java.util.Objects;

/**
 * Raw packet read directly from the capture source, including its PCAP header and raw byte payload.
 */
public final class RawPacket {

    private final PcapPacketHeader header;
    private final byte[] data;

    public RawPacket(PcapPacketHeader header, byte[] data) {
        this.header = Objects.requireNonNull(header, "header cannot be null");
        this.data = Objects.requireNonNull(data, "data cannot be null");
    }

    public PcapPacketHeader getHeader() {
        return header;
    }

    public byte[] getData() {
        return data;
    }

    public int getLength() {
        return data.length;
    }

    public long getTimestampSec() {
        return header.tsSec();
    }

    public long getTimestampUsec() {
        return header.tsUsec();
    }

    @Override
    public String toString() {
        return "RawPacket[len=" + data.length + ", ts=" + header.tsSec() + "." + header.tsUsec() + "]";
    }
}
