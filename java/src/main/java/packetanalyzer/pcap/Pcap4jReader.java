package packetanalyzer.pcap;

import packetanalyzer.model.PcapGlobalHeader;
import packetanalyzer.model.PcapPacketHeader;
import packetanalyzer.model.RawPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * Pcap4J-backed PCAP reader implementation.
 * Wraps Pcap4J offline handle when native libpcap / Npcap is available in the environment.
 */
public class Pcap4jReader implements PcapReader {

    private static final Logger logger = LoggerFactory.getLogger(Pcap4jReader.class);

    private PcapHandle handle;
    private PcapGlobalHeader globalHeader;
    private boolean open = false;

    @Override
    public void open(File file) throws IOException {
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("PCAP file not found: " + (file != null ? file.getPath() : "null"));
        }
        close();

        try {
            this.handle = Pcaps.openOffline(file.getAbsolutePath());
            int major = 2;
            int minor = 4;
            try {
                major = handle.getMajorVersion();
                minor = handle.getMinorVersion();
            } catch (NotOpenException ignored) {}
            this.globalHeader = new PcapGlobalHeader(
                PcapGlobalHeader.MAGIC_NATIVE,
                major,
                minor,
                0,
                0,
                65535L,
                1 // Ethernet
            );
            this.open = true;
        } catch (PcapNativeException | UnsatisfiedLinkError e) {
            logger.warn("Pcap4J native offline open failed (native libpcap/wpcap not available). " +
                        "Falling back to DefaultPcapReader recommended: {}", e.getMessage());
            throw new IOException("Pcap4J initialization failed: " + e.getMessage(), e);
        }
    }

    @Override
    public RawPacket readNextPacket() throws IOException {
        if (!open || handle == null) {
            return null;
        }
        try {
            org.pcap4j.packet.Packet p4jPacket = handle.getNextPacket();
            if (p4jPacket == null) {
                return null;
            }
            byte[] rawBytes = p4jPacket.getRawData();
            long sec = handle.getTimestamp().getTime() / 1000L;
            long usec = (handle.getTimestamp().getTime() % 1000L) * 1000L;

            PcapPacketHeader header = new PcapPacketHeader(sec, usec, rawBytes.length, rawBytes.length);
            return new RawPacket(header, rawBytes);
        } catch (Exception e) {
            throw new IOException("Error reading next packet with Pcap4J: " + e.getMessage(), e);
        }
    }

    @Override
    public PcapGlobalHeader getGlobalHeader() {
        return globalHeader;
    }

    @Override
    public boolean isOpen() {
        return open;
    }

    @Override
    public void close() throws IOException {
        if (handle != null) {
            try {
                handle.close();
            } finally {
                handle = null;
                open = false;
            }
        }
    }
}
