package packetanalyzer;

import packetanalyzer.dpi.DpiEngine;
import packetanalyzer.model.AppType;
import packetanalyzer.pcap.DefaultPcapReader;
import packetanalyzer.rules.RuleManager;
import packetanalyzer.stats.DpiStatistics;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DpiEngineEndToEndTest {

    private File findSamplePcap() {
        File[] candidates = new File[] {
            new File("../test_dpi.pcap"),
            new File("test_dpi.pcap"),
            new File("../Packet_analyzer-main/test_dpi.pcap")
        };
        for (File candidate : candidates) {
            if (candidate.exists()) {
                return candidate;
            }
        }
        throw new IllegalStateException("Sample PCAP test_dpi.pcap not found in workspace");
    }

    @Test
    void testProcessSamplePcapWithoutRules(@TempDir Path tempDir) throws IOException {
        File samplePcap = findSamplePcap();
        File outputPcap = tempDir.resolve("forwarded.pcap").toFile();

        DpiEngine engine = new DpiEngine();
        boolean success = engine.processFile(samplePcap.getAbsolutePath(), outputPcap.getAbsolutePath());

        assertThat(success).isTrue();

        DpiStatistics stats = engine.getStatistics();
        assertThat(stats.getTotalPackets()).isEqualTo(77);
        assertThat(stats.getForwardedPackets()).isEqualTo(77);
        assertThat(stats.getDroppedPackets()).isEqualTo(0);
        assertThat(stats.getDropRate()).isEqualTo(0.0);
        assertThat(stats.getActiveConnections()).isGreaterThan(0);

        // Verify Application Distribution was identified
        Map<AppType, Long> appDist = engine.getStatsService().getApplicationDistribution();
        assertThat(appDist).isNotEmpty();

        // Check that filtered output PCAP is a valid readable PCAP with 77 packets
        try (DefaultPcapReader outReader = new DefaultPcapReader()) {
            outReader.open(outputPcap);
            int count = 0;
            while (outReader.readNextPacket() != null) {
                count++;
            }
            assertThat(count).isEqualTo(77);
        }
    }

    @Test
    void testProcessSamplePcapWithBlocking(@TempDir Path tempDir) throws IOException {
        File samplePcap = findSamplePcap();
        File outputPcap = tempDir.resolve("filtered.pcap").toFile();

        RuleManager ruleManager = new RuleManager();
        // Block YouTube traffic
        ruleManager.blockApp(AppType.YOUTUBE);

        DpiEngine engine = new DpiEngine(ruleManager);
        boolean success = engine.processFile(samplePcap.getAbsolutePath(), outputPcap.getAbsolutePath());

        assertThat(success).isTrue();

        DpiStatistics stats = engine.getStatistics();
        assertThat(stats.getTotalPackets()).isEqualTo(77);
        assertThat(stats.getDroppedPackets()).isGreaterThan(0);
        assertThat(stats.getForwardedPackets()).isLessThan(77);
        assertThat(stats.getForwardedPackets() + stats.getDroppedPackets()).isEqualTo(77);

        // Verify output PCAP has only the forwarded packets
        try (DefaultPcapReader outReader = new DefaultPcapReader()) {
            outReader.open(outputPcap);
            int count = 0;
            while (outReader.readNextPacket() != null) {
                count++;
            }
            assertThat(count).isEqualTo((int) stats.getForwardedPackets());
        }
    }

    @Test
    void testProcessWithPacketLimit(@TempDir Path tempDir) throws IOException {
        File samplePcap = findSamplePcap();
        File outputPcap = tempDir.resolve("limited.pcap").toFile();

        DpiEngine engine = new DpiEngine();
        engine.setPacketLimit(20);
        boolean success = engine.processFile(samplePcap.getAbsolutePath(), outputPcap.getAbsolutePath());

        assertThat(success).isTrue();
        assertThat(engine.getStatistics().getTotalPackets()).isEqualTo(20);
    }
}
