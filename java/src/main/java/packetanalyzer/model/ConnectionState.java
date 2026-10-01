package packetanalyzer.model;

/**
 * State of a network connection / flow.
 * Mirrors the C++ ConnectionState enum from types.h.
 */
public enum ConnectionState {
    NEW,
    ESTABLISHED,
    CLASSIFIED,
    BLOCKED,
    CLOSED
}
