package packetanalyzer.rules;

/**
 * Encapsulates the specific reason and policy match when a packet or flow is blocked.
 */
public record BlockReason(Type type, String detail) {

    public enum Type {
        IP,
        APP,
        DOMAIN,
        PORT
    }

    @Override
    public String toString() {
        return type + " (" + detail + ")";
    }
}
