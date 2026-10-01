package packetanalyzer.model;

/**
 * Action to take on a packet.
 * Mirrors C++ PacketAction enum from types.h.
 */
public enum PacketAction {
    FORWARD,    // Forward packet to destination
    DROP,       // Drop / block the packet
    INSPECT,    // Needs further inspection
    LOG_ONLY    // Forward but log for auditing
}
