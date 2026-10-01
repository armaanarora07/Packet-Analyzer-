package packetanalyzer.dpi;

import packetanalyzer.model.AppType;

/**
 * Classifies network flows into application categories based on domain names,
 * Server Name Indication (SNI), HTTP Host headers, or destination ports.
 *
 * <p>Direct equivalent of the C++ {@code sniToAppType} function in types.cpp.</p>
 */
public final class ApplicationClassifier {

    private ApplicationClassifier() {
        // Utility
    }

    /**
     * Maps an extracted SNI or HTTP host to an {@link AppType}.
     *
     * @param hostname Server name / domain string
     * @return Classified {@link AppType}
     */
    public static AppType classifyFromDomain(String hostname) {
        if (hostname == null || hostname.trim().isEmpty()) {
            return AppType.UNKNOWN;
        }

        String lower = hostname.toLowerCase();

        // 1. YouTube (check before generic Google because YouTube is owned by Google)
        if (lower.contains("youtube") ||
            lower.contains("ytimg") ||
            lower.contains("youtu.be") ||
            lower.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }

        // 2. Google
        if (lower.contains("google") ||
            lower.contains("gstatic") ||
            lower.contains("googleapis") ||
            lower.contains("ggpht") ||
            lower.contains("gvt1")) {
            return AppType.GOOGLE;
        }

        // 3. Instagram
        if (lower.contains("instagram") ||
            lower.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }

        // 4. WhatsApp
        if (lower.contains("whatsapp") ||
            lower.contains("wa.me")) {
            return AppType.WHATSAPP;
        }

        // 5. Facebook / Meta
        if (lower.contains("facebook") ||
            lower.contains("fbcdn") ||
            lower.contains("fb.com") ||
            lower.contains("fbsbx") ||
            lower.contains("meta.com")) {
            return AppType.FACEBOOK;
        }

        // 6. Netflix (checked before Twitter/x.com so netflix.com doesn't match substring "x.com")
        if (lower.contains("netflix") ||
            lower.contains("nflxvideo") ||
            lower.contains("nflximg")) {
            return AppType.NETFLIX;
        }

        // 7. Twitter / X
        if (lower.contains("twitter") ||
            lower.contains("twimg") ||
            lower.contains("x.com") ||
            lower.contains("t.co")) {
            return AppType.TWITTER;
        }

        // 8. Amazon
        if (lower.contains("amazon") ||
            lower.contains("amazonaws") ||
            lower.contains("cloudfront") ||
            lower.contains("aws")) {
            return AppType.AMAZON;
        }

        // 9. Microsoft
        if (lower.contains("microsoft") ||
            lower.contains("msn.com") ||
            lower.contains("office") ||
            lower.contains("azure") ||
            lower.contains("live.com") ||
            lower.contains("outlook") ||
            lower.contains("bing")) {
            return AppType.MICROSOFT;
        }

        // 10. Apple
        if (lower.contains("apple") ||
            lower.contains("icloud") ||
            lower.contains("mzstatic") ||
            lower.contains("itunes")) {
            return AppType.APPLE;
        }

        // 11. Telegram
        if (lower.contains("telegram") ||
            lower.contains("t.me")) {
            return AppType.TELEGRAM;
        }

        // 12. TikTok
        if (lower.contains("tiktok") ||
            lower.contains("tiktokcdn") ||
            lower.contains("musical.ly") ||
            lower.contains("bytedance")) {
            return AppType.TIKTOK;
        }

        // 13. Spotify
        if (lower.contains("spotify") ||
            lower.contains("scdn.co")) {
            return AppType.SPOTIFY;
        }

        // 14. Zoom
        if (lower.contains("zoom")) {
            return AppType.ZOOM;
        }

        // 15. Discord
        if (lower.contains("discord") ||
            lower.contains("discordapp")) {
            return AppType.DISCORD;
        }

        // 16. GitHub
        if (lower.contains("github") ||
            lower.contains("githubusercontent")) {
            return AppType.GITHUB;
        }

        // 17. Cloudflare
        if (lower.contains("cloudflare") ||
            lower.contains("cf-")) {
            return AppType.CLOUDFLARE;
        }

        // Default: If an SNI is present on TLS port, classify as HTTPS
        return AppType.HTTPS;
    }

    /**
     * Fallback classification based on standard well-known destination ports.
     */
    public static AppType classifyFromPort(int dstPort) {
        return switch (dstPort) {
            case 80, 8080 -> AppType.HTTP;
            case 443, 8443 -> AppType.HTTPS;
            case 53 -> AppType.DNS;
            default -> AppType.UNKNOWN;
        };
    }
}
