package packetanalyzer.rules;

import packetanalyzer.model.AppType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * Manages traffic filtering and blocking rules:
 * IP addresses, application types, domain names (with wildcard support), and ports.
 *
 * <p>Direct equivalent of the C++ {@code RuleManager} class.</p>
 */
public class RuleManager {

    private static final Logger logger = LoggerFactory.getLogger(RuleManager.class);

    private final Set<String> blockedIps = new CopyOnWriteArraySet<>();
    private final Set<AppType> blockedApps = new CopyOnWriteArraySet<>();
    private final Set<String> blockedExactDomains = new CopyOnWriteArraySet<>();
    private final List<String> domainWildcardPatterns = new CopyOnWriteArrayList<>();
    private final Set<Integer> blockedPorts = new CopyOnWriteArraySet<>();

    public RuleManager() {
    }

    // ==================== IP Blocking ====================

    public void blockIp(String ip) {
        if (ip != null && !ip.trim().isEmpty()) {
            blockedIps.add(ip.trim());
            logger.info("[RuleManager] Blocked IP: {}", ip.trim());
        }
    }

    public void unblockIp(String ip) {
        if (ip != null) {
            blockedIps.remove(ip.trim());
            logger.info("[RuleManager] Unblocked IP: {}", ip.trim());
        }
    }

    public boolean isIpBlocked(String ip) {
        return ip != null && blockedIps.contains(ip.trim());
    }

    public Set<String> getBlockedIps() {
        return Collections.unmodifiableSet(blockedIps);
    }

    // ==================== App Blocking ====================

    public void blockApp(AppType app) {
        if (app != null && app != AppType.UNKNOWN) {
            blockedApps.add(app);
            logger.info("[RuleManager] Blocked App: {}", app.getDisplayName());
        }
    }

    public void unblockApp(AppType app) {
        if (app != null) {
            blockedApps.remove(app);
            logger.info("[RuleManager] Unblocked App: {}", app.getDisplayName());
        }
    }

    public boolean isAppBlocked(AppType app) {
        return app != null && blockedApps.contains(app);
    }

    public Set<AppType> getBlockedApps() {
        return Collections.unmodifiableSet(blockedApps);
    }

    // ==================== Domain Blocking ====================

    public void blockDomain(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return;
        }
        String clean = domain.trim().toLowerCase();
        if (clean.contains("*")) {
            if (!domainWildcardPatterns.contains(clean)) {
                domainWildcardPatterns.add(clean);
            }
        } else {
            blockedExactDomains.add(clean);
        }
        logger.info("[RuleManager] Blocked Domain: {}", clean);
    }

    public void unblockDomain(String domain) {
        if (domain == null) return;
        String clean = domain.trim().toLowerCase();
        blockedExactDomains.remove(clean);
        domainWildcardPatterns.remove(clean);
        logger.info("[RuleManager] Unblocked Domain: {}", clean);
    }

    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.trim().isEmpty()) {
            return false;
        }
        String lower = domain.trim().toLowerCase();

        // Exact match
        if (blockedExactDomains.contains(lower)) {
            return true;
        }

        // Wildcard patterns (e.g. *.facebook.com)
        for (String pattern : domainWildcardPatterns) {
            if (matchesDomainPattern(lower, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Matches domain against pattern (e.g. "*.example.com" matches "sub.example.com" and "example.com").
     */
    private boolean matchesDomainPattern(String domain, String pattern) {
        if (pattern.startsWith("*.")) {
            String suffix = pattern.substring(1); // ".example.com"
            if (domain.endsWith(suffix)) {
                return true;
            }
            // Bare domain match (example.com matches *.example.com)
            String bare = pattern.substring(2); // "example.com"
            return domain.equals(bare);
        }
        // Substring fallback
        return domain.contains(pattern);
    }

    public List<String> getBlockedDomains() {
        List<String> all = new ArrayList<>(blockedExactDomains);
        all.addAll(domainWildcardPatterns);
        return Collections.unmodifiableList(all);
    }

    // ==================== Port Blocking ====================

    public void blockPort(int port) {
        if (port > 0 && port <= 65535) {
            blockedPorts.add(port);
            logger.info("[RuleManager] Blocked Port: {}", port);
        }
    }

    public void unblockPort(int port) {
        blockedPorts.remove(port);
        logger.info("[RuleManager] Unblocked Port: {}", port);
    }

    public boolean isPortBlocked(int port) {
        return blockedPorts.contains(port);
    }

    public Set<Integer> getBlockedPorts() {
        return Collections.unmodifiableSet(blockedPorts);
    }

    // ==================== Combined Evaluation ====================

    /**
     * Evaluates a packet/flow against all rules in priority order:
     * 1. Source IP
     * 2. Destination Port
     * 3. Application Type
     * 4. Domain / SNI
     *
     * @return {@link Optional} containing {@link BlockReason} if blocked, or empty if allowed
     */
    public Optional<BlockReason> shouldBlock(String srcIp, int dstPort, AppType app, String domain) {
        // 1. IP Check (most specific)
        if (isIpBlocked(srcIp)) {
            return Optional.of(new BlockReason(BlockReason.Type.IP, srcIp));
        }

        // 2. Port Check
        if (isPortBlocked(dstPort)) {
            return Optional.of(new BlockReason(BlockReason.Type.PORT, String.valueOf(dstPort)));
        }

        // 3. Application Check
        if (isAppBlocked(app)) {
            return Optional.of(new BlockReason(BlockReason.Type.APP, app.getDisplayName()));
        }

        // 4. Domain Check
        if (domain != null && !domain.isEmpty() && isDomainBlocked(domain)) {
            return Optional.of(new BlockReason(BlockReason.Type.DOMAIN, domain));
        }

        return Optional.empty();
    }

    // ==================== Persistence ====================

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedExactDomains.clear();
        domainWildcardPatterns.clear();
        blockedPorts.clear();
        logger.info("[RuleManager] Cleared all rules");
    }

    public boolean saveRules(File file) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write("[BLOCKED_IPS]\n");
            for (String ip : blockedIps) {
                writer.write(ip);
                writer.write("\n");
            }

            writer.write("\n[BLOCKED_APPS]\n");
            for (AppType app : blockedApps) {
                writer.write(app.getDisplayName());
                writer.write("\n");
            }

            writer.write("\n[BLOCKED_DOMAINS]\n");
            for (String domain : getBlockedDomains()) {
                writer.write(domain);
                writer.write("\n");
            }

            writer.write("\n[BLOCKED_PORTS]\n");
            for (int port : blockedPorts) {
                writer.write(String.valueOf(port));
                writer.write("\n");
            }
            return true;
        } catch (IOException e) {
            logger.error("Failed to save rules to file {}: {}", file.getPath(), e.getMessage());
            return false;
        }
    }

    public boolean loadRules(File file) {
        if (!file.exists()) {
            logger.warn("Rule file {} does not exist", file.getPath());
            return false;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            String currentSection = "";

            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("[") && line.endsWith("]")) {
                    currentSection = line;
                    continue;
                }

                switch (currentSection) {
                    case "[BLOCKED_IPS]" -> blockIp(line);
                    case "[BLOCKED_APPS]" -> {
                        AppType type = AppType.fromString(line);
                        if (type != AppType.UNKNOWN) {
                            blockApp(type);
                        }
                    }
                    case "[BLOCKED_DOMAINS]" -> blockDomain(line);
                    case "[BLOCKED_PORTS]" -> {
                        try {
                            blockPort(Integer.parseInt(line));
                        } catch (NumberFormatException ignored) {}
                    }
                }
            }
            logger.info("[RuleManager] Rules loaded successfully from {}", file.getPath());
            return true;
        } catch (IOException e) {
            logger.error("Failed to load rules from file {}: {}", file.getPath(), e.getMessage());
            return false;
        }
    }

    public record RuleStats(int blockedIps, int blockedApps, int blockedDomains, int blockedPorts) {}

    public RuleStats getStats() {
        return new RuleStats(
            blockedIps.size(),
            blockedApps.size(),
            blockedExactDomains.size() + domainWildcardPatterns.size(),
            blockedPorts.size()
        );
    }
}
