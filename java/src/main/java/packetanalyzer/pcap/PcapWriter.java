package packetanalyzer.pcap;

import packetanalyzer.model.PcapGlobalHeader;
import packetanalyzer.model.RawPacket;

import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Pure Java binary PCAP file writer for emitting filtered / forwarded packets.
 */
public class PcapWriter implements Closeable {

    private final OutputStream outputStream;
    private final ByteOrder byteOrder;
    private boolean headerWritten = false;

    public PcapWriter(File file, ByteOrder byteOrder) throws IOException {
        this.outputStream = new BufferedOutputStream(new FileOutputStream(file));
        this.byteOrder = byteOrder != null ? byteOrder : ByteOrder.LITTLE_ENDIAN;
    }

    public PcapWriter(String filePath) throws IOException {
        this(new File(filePath), ByteOrder.LITTLE_ENDIAN);
    }

    public synchronized void writeGlobalHeader(PcapGlobalHeader header) throws IOException {
        if (headerWritten) {
            return;
        }
        ByteBuffer buf = ByteBuffer.allocate(24).order(this.byteOrder);
        long magic = (this.byteOrder == ByteOrder.LITTLE_ENDIAN) ? 0xa1b2c3d4L : 0xd4c3b2a1L;
        buf.putInt((int) magic);
        buf.putShort((short) (header != null ? header.versionMajor() : 2));
        buf.putShort((short) (header != null ? header.versionMinor() : 4));
        buf.putInt(header != null ? header.thisZone() : 0);
        buf.putInt((int) (header != null ? header.sigFigs() : 0));
        buf.putInt((int) (header != null ? header.snapLen() : 65535));
        buf.putInt((int) (header != null ? header.network() : 1)); // 1 = Ethernet

        outputStream.write(buf.array());
        headerWritten = true;
    }

    public synchronized void writePacket(RawPacket packet) throws IOException {
        if (!headerWritten) {
            writeGlobalHeader(null);
        }
        byte[] data = packet.getData();
        ByteBuffer buf = ByteBuffer.allocate(16).order(this.byteOrder);
        buf.putInt((int) packet.getTimestampSec());
        buf.putInt((int) packet.getTimestampUsec());
        buf.putInt(data.length);
        buf.putInt(data.length);

        outputStream.write(buf.array());
        outputStream.write(data);
    }

    public synchronized void flush() throws IOException {
        outputStream.flush();
    }

    @Override
    public synchronized void close() throws IOException {
        try {
            outputStream.flush();
        } finally {
            outputStream.close();
        }
    }
}
