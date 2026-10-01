package packetanalyzer.pcap;

import packetanalyzer.model.PcapGlobalHeader;
import packetanalyzer.model.RawPacket;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;

/**
 * Common interface for reading PCAP captures.
 * Exposes packet information without forcing the rest of the application
 * to know how the PCAP file is read.
 */
public interface PcapReader extends Closeable {

    /**
     * Opens a PCAP file from the file system.
     *
     * @param file Target file
     * @throws IOException If file cannot be read or has invalid format
     */
    void open(File file) throws IOException;

    /**
     * Opens a PCAP file by file path string.
     *
     * @param filePath Path to file
     * @throws IOException If file cannot be read or has invalid format
     */
    default void open(String filePath) throws IOException {
        open(new File(filePath));
    }

    /**
     * Reads the next raw packet from the PCAP stream.
     *
     * @return Next {@link RawPacket}, or {@code null} if end of capture reached
     * @throws IOException On malformed header or truncated stream
     */
    RawPacket readNextPacket() throws IOException;

    /**
     * Returns the parsed 24-byte PCAP Global Header.
     */
    PcapGlobalHeader getGlobalHeader();

    /**
     * Returns {@code true} if the reader is currently open.
     */
    boolean isOpen();
}
