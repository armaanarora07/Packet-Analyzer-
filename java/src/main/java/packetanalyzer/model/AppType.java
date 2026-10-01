package packetanalyzer.model;

/**
 * Enumeration of application types classified by the DPI engine.
 * Mirrors the C++ AppType enum from types.h.
 */
public enum AppType {
    UNKNOWN("Unknown"),
    HTTP("HTTP"),
    HTTPS("HTTPS"),
    DNS("DNS"),
    TLS("TLS"),
    QUIC("QUIC"),
    GOOGLE("Google"),
    FACEBOOK("Facebook"),
    YOUTUBE("YouTube"),
    TWITTER("Twitter/X"),
    INSTAGRAM("Instagram"),
    NETFLIX("Netflix"),
    AMAZON("Amazon"),
    MICROSOFT("Microsoft"),
    APPLE("Apple"),
    WHATSAPP("WhatsApp"),
    TELEGRAM("Telegram"),
    TIKTOK("TikTok"),
    SPOTIFY("Spotify"),
    ZOOM("Zoom"),
    DISCORD("Discord"),
    GITHUB("GitHub"),
    CLOUDFLARE("Cloudflare");

    private final String displayName;

    AppType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public static AppType fromString(String name) {
        if (name == null || name.trim().isEmpty()) {
            return UNKNOWN;
        }
        for (AppType type : values()) {
            if (type.name().equalsIgnoreCase(name.trim()) ||
                type.displayName.equalsIgnoreCase(name.trim())) {
                return type;
            }
        }
        return UNKNOWN;
    }
}
