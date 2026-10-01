package packetanalyzer;

import packetanalyzer.model.AppType;
import packetanalyzer.rules.BlockReason;
import packetanalyzer.rules.RuleManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Path;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RuleManagerTest {

    @Test
    void testIpBlocking() {
        RuleManager rm = new RuleManager();
        rm.blockIp("192.168.1.50");

        assertThat(rm.isIpBlocked("192.168.1.50")).isTrue();
        assertThat(rm.isIpBlocked("192.168.1.51")).isFalse();

        rm.unblockIp("192.168.1.50");
        assertThat(rm.isIpBlocked("192.168.1.50")).isFalse();
    }

    @Test
    void testAppBlocking() {
        RuleManager rm = new RuleManager();
        rm.blockApp(AppType.YOUTUBE);

        assertThat(rm.isAppBlocked(AppType.YOUTUBE)).isTrue();
        assertThat(rm.isAppBlocked(AppType.NETFLIX)).isFalse();

        rm.unblockApp(AppType.YOUTUBE);
        assertThat(rm.isAppBlocked(AppType.YOUTUBE)).isFalse();
    }

    @Test
    void testDomainBlockingWithWildcards() {
        RuleManager rm = new RuleManager();
        rm.blockDomain("*.facebook.com");
        rm.blockDomain("badsite.org");

        // Wildcard subdomain matching
        assertThat(rm.isDomainBlocked("static.facebook.com")).isTrue();
        assertThat(rm.isDomainBlocked("facebook.com")).isTrue(); // Bare domain match
        assertThat(rm.isDomainBlocked("myfacebook.com")).isFalse(); // Not a subdomain

        // Exact match
        assertThat(rm.isDomainBlocked("badsite.org")).isTrue();
        assertThat(rm.isDomainBlocked("goodsite.org")).isFalse();
    }

    @Test
    void testPortBlocking() {
        RuleManager rm = new RuleManager();
        rm.blockPort(8080);

        assertThat(rm.isPortBlocked(8080)).isTrue();
        assertThat(rm.isPortBlocked(80)).isFalse();

        rm.unblockPort(8080);
        assertThat(rm.isPortBlocked(8080)).isFalse();
    }

    @Test
    void testShouldBlockPriorityAndReason() {
        RuleManager rm = new RuleManager();
        rm.blockIp("192.168.1.100");
        rm.blockApp(AppType.TIKTOK);
        rm.blockDomain("*.discord.com");
        rm.blockPort(445);

        // 1. IP rule triggered
        Optional<BlockReason> r1 = rm.shouldBlock("192.168.1.100", 80, AppType.HTTP, "");
        assertThat(r1).isPresent();
        assertThat(r1.get().type()).isEqualTo(BlockReason.Type.IP);

        // 2. Port rule triggered
        Optional<BlockReason> r2 = rm.shouldBlock("10.0.0.1", 445, AppType.UNKNOWN, "");
        assertThat(r2).isPresent();
        assertThat(r2.get().type()).isEqualTo(BlockReason.Type.PORT);

        // 3. App rule triggered
        Optional<BlockReason> r3 = rm.shouldBlock("10.0.0.1", 443, AppType.TIKTOK, "tiktok.com");
        assertThat(r3).isPresent();
        assertThat(r3.get().type()).isEqualTo(BlockReason.Type.APP);

        // 4. Domain rule triggered
        Optional<BlockReason> r4 = rm.shouldBlock("10.0.0.1", 443, AppType.HTTPS, "gateway.discord.com");
        assertThat(r4).isPresent();
        assertThat(r4.get().type()).isEqualTo(BlockReason.Type.DOMAIN);

        // 5. Allowed
        Optional<BlockReason> r5 = rm.shouldBlock("10.0.0.1", 443, AppType.GITHUB, "github.com");
        assertThat(r5).isEmpty();
    }

    @Test
    void testSaveAndLoadRules(@TempDir Path tempDir) {
        RuleManager rm1 = new RuleManager();
        rm1.blockIp("192.168.1.200");
        rm1.blockApp(AppType.SPOTIFY);
        rm1.blockDomain("*.tiktok.com");
        rm1.blockPort(8888);

        File rulesFile = tempDir.resolve("test_rules.txt").toFile();
        boolean saved = rm1.saveRules(rulesFile);
        assertThat(saved).isTrue();

        RuleManager rm2 = new RuleManager();
        boolean loaded = rm2.loadRules(rulesFile);
        assertThat(loaded).isTrue();

        assertThat(rm2.isIpBlocked("192.168.1.200")).isTrue();
        assertThat(rm2.isAppBlocked(AppType.SPOTIFY)).isTrue();
        assertThat(rm2.isDomainBlocked("v.tiktok.com")).isTrue();
        assertThat(rm2.isPortBlocked(8888)).isTrue();
    }
}
