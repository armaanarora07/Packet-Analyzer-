package packetanalyzer.pcap;

import packetanalyzer.model.PcapGlobalHeader;
import packetanalyzer.model.PcapPacketHeader;
import packetanalyzer.model.RawPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Pure Java PCAP file reader implementing standard binary libpcap parsing.
 * Supports both native and swapped byte orders without requiring native WinPcap/Npcap/libpcap libraries.
 */
public class DefaultPcapReader implements PcapReader {

    private static final Logger logger = LoggerFactory.getLogger(DefaultPcapReader.class);

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    private InputStream inputStream;
    private PcapGlobalHeader globalHeader;
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;
    private boolean open = false;

    @Override
    public void open(File file) throws IOException {
        if (file == null || !file.exists()) {
            throw new FileNotFoundException("PCAP file not found: " + (file != null ? file.getPath() : "null"));
        }
        close();

        this.inputStream = new BufferedInputStream(new FileInputStream(file));
        readGlobalHeader();
        this.open = true;
    }

    private void readGlobalHeader() throws IOException {
        byte[] headerBytes = new byte[GLOBAL_HEADER_SIZE];
        int bytesRead = readFully(headerBytes);
        if (bytesRead < GLOBAL_HEADER_SIZE) {
            throw new IOException("Unexpected end of file while reading PCAP global header");
        }

        // Determine byte order from magic number
        ByteBuffer probe = ByteBuffer.wrap(headerBytes);
        int magic = probe.getInt();

        if (magic == 0xa1b2c3d4) {
            this.byteOrder = ByteOrder.BIG_ENDIAN;
        } else if (magic == 0xd4c3b2a1) {
            this.byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else {
            throw new IOException(String.format("Invalid PCAP magic number: 0x%08X", magic));
        }

        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(this.byteOrder);
        long magicNumber = Integer.toUnsignedLong(buf.getInt());
        int versionMajor = buf.getShort() & 0xFFFF;
        int versionMinor = buf.getShort() & 0xFFFF;
        int thisZone = buf.getInt();
        long sigFigs = Integer.toUnsignedLong(buf.getInt());
        long snapLen = Integer.toUnsignedLong(buf.getInt());
        long network = Integer.toUnsignedLong(buf.getInt());

        this.globalHeader = new PcapGlobalHeader(
            magicNumber,
            versionMajor,
            versionMinor,
            thisZone,
            sigFigs,
            snapLen,
            network
        );

        logger.debug("Opened PCAP capture: v{}.{}, snapLen={}, linkType={}",
            versionMajor, versionMinor, snapLen, network);
    }

    @Override
    public RawPacket readNextPacket() throws IOException {
        if (!open || inputStream == null) {
            return null;
        }

        byte[] headerBytes = new byte[PACKET_HEADER_SIZE];
        int bytesRead = inputStream.read(headerBytes, 0, PACKET_HEADER_SIZE);
        if (bytesRead == -1) {
            // Clean EOF
            return null;
        }
        if (bytesRead < PACKET_HEADER_SIZE) {
            int remaining = PACKET_HEADER_SIZE - bytesRead;
            int additional = readFullyDirect(headerBytes, bytesRead, remaining);
            if (additional < remaining) {
                logger.warn("Truncated packet header at end of file (read {} of {} bytes)",
                    bytesRead + additional, PACKET_HEADER_SIZE);
                return null;
            }
        }

        ByteBuffer buf = ByteBuffer.wrap(headerBytes).order(this.byteOrder);
        long tsSec = Integer.toUnsignedLong(buf.getInt());
        long tsUsec = Integer.toUnsignedLong(buf.getInt());
        int inclLen = buf.getInt();
        int origLen = buf.getInt();

        // Length validation and bounds checking
        if (inclLen < 0 || (globalHeader != null && inclLen > globalHeader.snapLen()) || inclLen > 65535) {
            logger.warn("Corrupted or invalid packet length in PCAP: {} bytes (snapLen={})",
                inclLen, globalHeader != null ? globalHeader.snapLen() : "unknown");
            return null;
        }

        byte[] packetData = new byte[inclLen];
        int dataRead = readFully(packetData);
        if (dataRead < inclLen) {
            logger.warn("Premature EOF reading packet data: expected {} bytes, got {}", inclLen, dataRead);
            return null;
        }

        PcapPacketHeader packetHeader = new PcapPacketHeader(tsSec, tsUsec, inclLen, origLen);
        return new RawPacket(packetHeader, packetData);
    }

    private int readFully(byte[] target) throws IOException {
        return readFullyDirect(target, 0, target.length);
    }

    private int readFullyDirect(byte[] target, int offset, int length) throws IOException {
        int total = 0;
        while (total < length) {
            int count = inputStream.read(target, offset + total, length - total);
            if (count == -1) {
                break;
            }
            total += count;
        }
        return total;
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
        if (inputStream != null) {
            try {
                inputStream.close();
            } finally {
                inputStream = null;
                open = false;
            }
        }
    }
}
