package packetanalyzer;

import packetanalyzer.dpi.ApplicationClassifier;
import packetanalyzer.model.AppType;
import packetanalyzer.util.NetworkUtils;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ProtocolAndApplicationTest {

    @Test
    void testProtocolClassification() {
        assertThat(NetworkUtils.protocolToString(1)).isEqualTo("ICMP");
        assertThat(NetworkUtils.protocolToString(6)).isEqualTo("TCP");
        assertThat(NetworkUtils.protocolToString(17)).isEqualTo("UDP");
        assertThat(NetworkUtils.protocolToString(99)).isEqualTo("Unknown(99)");
    }

    @Test
    void testTcpFlagsToString() {
        assertThat(NetworkUtils.tcpFlagsToString(0x02)).isEqualTo("SYN");
        assertThat(NetworkUtils.tcpFlagsToString(0x12)).isEqualTo("SYN ACK");
        assertThat(NetworkUtils.tcpFlagsToString(0x11)).isEqualTo("ACK FIN");
        assertThat(NetworkUtils.tcpFlagsToString(0x04)).isEqualTo("RST");
        assertThat(NetworkUtils.tcpFlagsToString(0)).isEqualTo("none");
    }

    @Test
    void testApplicationClassificationByDomain() {
        assertThat(ApplicationClassifier.classifyFromDomain("www.youtube.com")).isEqualTo(AppType.YOUTUBE);
        assertThat(ApplicationClassifier.classifyFromDomain("i.ytimg.com")).isEqualTo(AppType.YOUTUBE);
        assertThat(ApplicationClassifier.classifyFromDomain("www.google.com")).isEqualTo(AppType.GOOGLE);
        assertThat(ApplicationClassifier.classifyFromDomain("fonts.gstatic.com")).isEqualTo(AppType.GOOGLE);
        assertThat(ApplicationClassifier.classifyFromDomain("api.facebook.com")).isEqualTo(AppType.FACEBOOK);
        assertThat(ApplicationClassifier.classifyFromDomain("scontent.cdninstagram.com")).isEqualTo(AppType.INSTAGRAM);
        assertThat(ApplicationClassifier.classifyFromDomain("web.whatsapp.com")).isEqualTo(AppType.WHATSAPP);
        assertThat(ApplicationClassifier.classifyFromDomain("twitter.com")).isEqualTo(AppType.TWITTER);
        assertThat(ApplicationClassifier.classifyFromDomain("x.com")).isEqualTo(AppType.TWITTER);
        assertThat(ApplicationClassifier.classifyFromDomain("www.netflix.com")).isEqualTo(AppType.NETFLIX);
        assertThat(ApplicationClassifier.classifyFromDomain("aws.amazon.com")).isEqualTo(AppType.AMAZON);
        assertThat(ApplicationClassifier.classifyFromDomain("login.microsoftonline.com")).isEqualTo(AppType.MICROSOFT);
        assertThat(ApplicationClassifier.classifyFromDomain("icloud.com")).isEqualTo(AppType.APPLE);
        assertThat(ApplicationClassifier.classifyFromDomain("t.me")).isEqualTo(AppType.TELEGRAM);
        assertThat(ApplicationClassifier.classifyFromDomain("tiktokcdn.com")).isEqualTo(AppType.TIKTOK);
        assertThat(ApplicationClassifier.classifyFromDomain("spotify.com")).isEqualTo(AppType.SPOTIFY);
        assertThat(ApplicationClassifier.classifyFromDomain("zoom.us")).isEqualTo(AppType.ZOOM);
        assertThat(ApplicationClassifier.classifyFromDomain("discord.com")).isEqualTo(AppType.DISCORD);
        assertThat(ApplicationClassifier.classifyFromDomain("github.com")).isEqualTo(AppType.GITHUB);
        assertThat(ApplicationClassifier.classifyFromDomain("cloudflare.com")).isEqualTo(AppType.CLOUDFLARE);

        // Unknown domain fallback
        assertThat(ApplicationClassifier.classifyFromDomain("some-custom-bank.com")).isEqualTo(AppType.HTTPS);
        assertThat(ApplicationClassifier.classifyFromDomain("")).isEqualTo(AppType.UNKNOWN);
        assertThat(ApplicationClassifier.classifyFromDomain(null)).isEqualTo(AppType.UNKNOWN);
    }

    @Test
    void testApplicationClassificationByPortFallback() {
        assertThat(ApplicationClassifier.classifyFromPort(80)).isEqualTo(AppType.HTTP);
        assertThat(ApplicationClassifier.classifyFromPort(443)).isEqualTo(AppType.HTTPS);
        assertThat(ApplicationClassifier.classifyFromPort(53)).isEqualTo(AppType.DNS);
        assertThat(ApplicationClassifier.classifyFromPort(22)).isEqualTo(AppType.UNKNOWN);
    }
}
