package packetanalyzer;

import packetanalyzer.model.FiveTuple;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class FiveTupleTest {

    @Test
    void testEqualityAndHashCode() {
        FiveTuple tuple1 = new FiveTuple("192.168.1.100", "142.250.190.46", 54321, 443, 6);
        FiveTuple tuple2 = new FiveTuple("192.168.1.100", "142.250.190.46", 54321, 443, 6);
        FiveTuple tupleDiffPort = new FiveTuple("192.168.1.100", "142.250.190.46", 54322, 443, 6);
        FiveTuple tupleDiffProto = new FiveTuple("192.168.1.100", "142.250.190.46", 54321, 443, 17);

        // Reflexive and Symmetric
        assertThat(tuple1).isEqualTo(tuple2);
        assertThat(tuple2).isEqualTo(tuple1);
        assertThat(tuple1.hashCode()).isEqualTo(tuple2.hashCode());

        // Inequality
        assertThat(tuple1).isNotEqualTo(tupleDiffPort);
        assertThat(tuple1).isNotEqualTo(tupleDiffProto);
    }

    @Test
    void testReverseFlowSymmetry() {
        FiveTuple forward = new FiveTuple("192.168.1.100", "142.250.190.46", 54321, 443, 6);
        FiveTuple reverse = forward.reverse();

        assertThat(reverse.getSrcIp()).isEqualTo("142.250.190.46");
        assertThat(reverse.getDstIp()).isEqualTo("192.168.1.100");
        assertThat(reverse.getSrcPort()).isEqualTo(443);
        assertThat(reverse.getDstPort()).isEqualTo(54321);
        assertThat(reverse.getProtocol()).isEqualTo(6);

        // Double reverse returns original
        assertThat(reverse.reverse()).isEqualTo(forward);
    }

    @Test
    void testHashMapAndSetKeyBehavior() {
        FiveTuple key = new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 80, 6);

        Set<FiveTuple> set = new HashSet<>();
        set.add(key);
        assertThat(set).contains(new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 80, 6));

        Map<FiveTuple, String> map = new HashMap<>();
        map.put(key, "HTTP-Flow-1");
        assertThat(map.get(new FiveTuple("10.0.0.1", "10.0.0.2", 1234, 80, 6))).isEqualTo("HTTP-Flow-1");
    }

    @Test
    void testToStringFormat() {
        FiveTuple tuple = new FiveTuple("192.168.1.5", "8.8.8.8", 5353, 53, 17);
        assertThat(tuple.toString()).isEqualTo("192.168.1.5:5353 -> 8.8.8.8:53 (UDP)");
    }
}
