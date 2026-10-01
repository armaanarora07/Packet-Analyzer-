package packetanalyzer.stats;

/**
 * Core statistics counters for DPI processing.
 *
 * <p>Per requirement #10: uses normal Java primitives for single-threaded processing,
 * with clear accessor methods prepared for UI/REST presentation.</p>
 */
public class DpiStatistics {

    private long totalPackets;
    private long totalBytes;
    private long forwardedPackets;
    private long droppedPackets;
    private long tcpPackets;
    private long udpPackets;
    private long otherPackets;
    private int activeConnections;

    public DpiStatistics() {
    }

    public synchronized void recordPacket(long bytes, boolean isTcp, boolean isUdp) {
        this.totalPackets++;
        this.totalBytes += bytes;
        if (isTcp) {
            this.tcpPackets++;
        } else if (isUdp) {
            this.udpPackets++;
        } else {
            this.otherPackets++;
        }
    }

    public synchronized void recordForwarded() {
        this.forwardedPackets++;
    }

    public synchronized void recordDropped() {
        this.droppedPackets++;
    }

    public synchronized void setActiveConnections(int activeConnections) {
        this.activeConnections = activeConnections;
    }

    public long getTotalPackets() {
        return totalPackets;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public long getForwardedPackets() {
        return forwardedPackets;
    }

    public long getDroppedPackets() {
        return droppedPackets;
    }

    public long getTcpPackets() {
        return tcpPackets;
    }

    public long getUdpPackets() {
        return udpPackets;
    }

    public long getOtherPackets() {
        return otherPackets;
    }

    public int getActiveConnections() {
        return activeConnections;
    }

    public double getDropRate() {
        return totalPackets > 0 ? (100.0 * droppedPackets / totalPackets) : 0.0;
    }

    public synchronized DpiStatistics snapshot() {
        DpiStatistics copy = new DpiStatistics();
        copy.totalPackets = this.totalPackets;
        copy.totalBytes = this.totalBytes;
        copy.forwardedPackets = this.forwardedPackets;
        copy.droppedPackets = this.droppedPackets;
        copy.tcpPackets = this.tcpPackets;
        copy.udpPackets = this.udpPackets;
        copy.otherPackets = this.otherPackets;
        copy.activeConnections = this.activeConnections;
        return copy;
    }

    @Override
    public String toString() {
        return String.format(
            "DpiStatistics[total=%d, bytes=%d, fwd=%d, drop=%d (%.2f%%), tcp=%d, udp=%d, flows=%d]",
            totalPackets, totalBytes, forwardedPackets, droppedPackets, getDropRate(), tcpPackets, udpPackets, activeConnections
        );
    }
}
