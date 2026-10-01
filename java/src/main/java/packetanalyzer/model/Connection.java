package packetanalyzer.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Tracks a persistent network flow / connection state between two endpoints.
 * Mirrors the C++ Connection struct from types.h.
 */
public final class Connection {

    private final FiveTuple tuple;
    private ConnectionState state;
    private AppType appType;
    private String sni;

    private long packetsIn;
    private long packetsOut;
    private long bytesIn;
    private long bytesOut;

    private Instant firstSeen;
    private Instant lastSeen;

    private PacketAction action;

    // TCP Handshake & Termination state flags
    private boolean synSeen;
    private boolean synAckSeen;
    private boolean finSeen;

    public Connection(FiveTuple tuple) {
        this.tuple = Objects.requireNonNull(tuple, "tuple cannot be null");
        this.state = ConnectionState.NEW;
        this.appType = AppType.UNKNOWN;
        this.sni = "";
        this.firstSeen = Instant.now();
        this.lastSeen = this.firstSeen;
        this.action = PacketAction.FORWARD;
    }

    public FiveTuple getTuple() {
        return tuple;
    }

    public ConnectionState getState() {
        return state;
    }

    public void setState(ConnectionState state) {
        this.state = state;
    }

    public AppType getAppType() {
        return appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public String getSni() {
        return sni;
    }

    public void setSni(String sni) {
        this.sni = sni != null ? sni : "";
    }

    public long getPacketsIn() {
        return packetsIn;
    }

    public long getPacketsOut() {
        return packetsOut;
    }

    public long getTotalPackets() {
        return packetsIn + packetsOut;
    }

    public long getBytesIn() {
        return bytesIn;
    }

    public long getBytesOut() {
        return bytesOut;
    }

    public long getTotalBytes() {
        return bytesIn + bytesOut;
    }

    public Instant getFirstSeen() {
        return firstSeen;
    }

    public Instant getLastSeen() {
        return lastSeen;
    }

    public PacketAction getAction() {
        return action;
    }

    public void setAction(PacketAction action) {
        this.action = action;
    }

    public boolean isSynSeen() {
        return synSeen;
    }

    public void setSynSeen(boolean synSeen) {
        this.synSeen = synSeen;
    }

    public boolean isSynAckSeen() {
        return synAckSeen;
    }

    public void setSynAckSeen(boolean synAckSeen) {
        this.synAckSeen = synAckSeen;
    }

    public boolean isFinSeen() {
        return finSeen;
    }

    public void setFinSeen(boolean finSeen) {
        this.finSeen = finSeen;
    }

    /**
     * Updates traffic volume and packet counts for this connection.
     */
    public void update(long packetSize, boolean isOutbound) {
        this.lastSeen = Instant.now();
        if (isOutbound) {
            this.packetsOut++;
            this.bytesOut += packetSize;
        } else {
            this.packetsIn++;
            this.bytesIn += packetSize;
        }
    }

    /**
     * Classifies the connection with an application type and optional SNI.
     */
    public void classify(AppType app, String detectedSni) {
        if (this.state != ConnectionState.CLASSIFIED) {
            this.appType = app;
            if (detectedSni != null && !detectedSni.isEmpty()) {
                this.sni = detectedSni;
            }
            this.state = ConnectionState.CLASSIFIED;
        }
    }

    /**
     * Marks this connection as blocked.
     */
    public void block() {
        this.state = ConnectionState.BLOCKED;
        this.action = PacketAction.DROP;
    }

    /**
     * Marks this connection as closed.
     */
    public void close() {
        this.state = ConnectionState.CLOSED;
    }
}
