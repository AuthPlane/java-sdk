package ai.authplane.sdk.core.fetching.ssrf;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

import ai.authplane.sdk.core.fetching.FetchSettings;

class IpValidatorTest {

    private static InetAddress ip(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static InetAddress ipRaw(byte[] addr) {
        try {
            return InetAddress.getByAddress(addr);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // -----------------------------------------------------------------------
    // IPv4 edge cases: carrier-grade NAT, IETF protocol assignments, 0.0.0.0/8
    // -----------------------------------------------------------------------

    @Test
    void ipv4_carrierGradeNat100_64_treatedAsPrivate() {
        // RFC 6598 100.64.0.0/10 — private when allowPrivateNetworks=false
        assertThat(IpValidator.isAllowed(ip("100.64.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("100.64.0.1"), FetchSettings.devMode())).isTrue();
        // 100.0.0.0 is not in 100.64.0.0/10 — globally routable
        assertThat(IpValidator.isAllowed(ip("100.0.0.1"), FetchSettings.production())).isTrue();
    }

    @Test
    void ipv4_ietfProtocolAssignments192_0_0_treatedAsPrivate() {
        assertThat(IpValidator.isAllowed(ip("192.0.0.5"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("192.0.0.5"), FetchSettings.devMode())).isTrue();
    }

    @Test
    void ipv4_unspecified0_treatedAsPrivate() {
        assertThat(IpValidator.isAllowed(ip("0.0.0.0"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("0.0.0.0"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // IPv6 embedded-IPv4 transition mechanisms
    // -----------------------------------------------------------------------

    @Test
    void ipv6_6to4WithPublicEmbeddedIpv4_isAllowed() {
        // 2002::/16 with embedded public IPv4 (8.8.8.8) → globally routable.
        byte[] v6 = new byte[16];
        v6[0] = 0x20;
        v6[1] = 0x02;
        v6[2] = 8;
        v6[3] = 8;
        v6[4] = 8;
        v6[5] = 8;
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.production())).isTrue();
    }

    @Test
    void ipv6_6to4WithPrivateEmbeddedIpv4_blocked() {
        // 2002::/16 with embedded RFC 1918 (10.0.0.1) — recursive check should
        // block as private.
        byte[] v6 = new byte[16];
        v6[0] = 0x20;
        v6[1] = 0x02;
        v6[2] = 10;
        v6[3] = 0;
        v6[4] = 0;
        v6[5] = 1;
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.production())).isFalse();
    }

    @Test
    void ipv6_teredoWithPrivateClientIp_blocked() {
        // 2001:0::/32 (Teredo) — client IPv4 is in bytes 12-15 XOR'd with 0xFF.
        // To represent 10.0.0.1 as the client IP, store its complement.
        byte[] v6 = new byte[16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x00;
        v6[3] = 0x00;
        v6[12] = (byte) (10 ^ 0xFF);
        v6[13] = (byte) (0 ^ 0xFF);
        v6[14] = (byte) (0 ^ 0xFF);
        v6[15] = (byte) (1 ^ 0xFF);
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.production())).isFalse();
    }

    @Test
    void ipv6_teredoWithPublicClientIp_allowed() {
        byte[] v6 = new byte[16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[2] = 0x00;
        v6[3] = 0x00;
        v6[12] = (byte) (8 ^ 0xFF);
        v6[13] = (byte) (8 ^ 0xFF);
        v6[14] = (byte) (8 ^ 0xFF);
        v6[15] = (byte) (8 ^ 0xFF);
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.production())).isTrue();
    }

    @Test
    void ipv6_unspecifiedAddress_treatedAsLocalhost() {
        byte[] v6 = new byte[16]; // all zeros = ::
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ipRaw(v6), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // Always-blocked (even in dev mode)
    // -----------------------------------------------------------------------

    @Test
    void alwaysBlocks_awsMetadata() {
        assertThat(IpValidator.isAllowed(ip("169.254.169.254"), FetchSettings.production()))
                .isFalse();
        assertThat(IpValidator.isAllowed(ip("169.254.169.254"), FetchSettings.devMode())).isFalse();
    }

    @Test
    void alwaysBlocks_linkLocal() {
        assertThat(IpValidator.isAllowed(ip("169.254.0.1"), FetchSettings.devMode())).isFalse();
        assertThat(IpValidator.isAllowed(ip("169.254.255.255"), FetchSettings.devMode())).isFalse();
    }

    @Test
    void alwaysBlocks_ipv4Multicast() {
        assertThat(IpValidator.isAllowed(ip("224.0.0.1"), FetchSettings.devMode())).isFalse();
        assertThat(IpValidator.isAllowed(ip("239.255.255.255"), FetchSettings.devMode())).isFalse();
    }

    @Test
    void alwaysBlocks_ipv6LinkLocal() {
        assertThat(IpValidator.isAllowed(ip("fe80::1"), FetchSettings.devMode())).isFalse();
        assertThat(IpValidator.isAllowed(ip("febf::1"), FetchSettings.devMode())).isFalse();
    }

    @Test
    void alwaysBlocks_ipv6Multicast() {
        assertThat(IpValidator.isAllowed(ip("ff02::1"), FetchSettings.devMode())).isFalse();
    }

    // -----------------------------------------------------------------------
    // Loopback
    // -----------------------------------------------------------------------

    @Test
    void blocks_loopback_inProduction() {
        assertThat(IpValidator.isAllowed(ip("127.0.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("127.255.255.255"), FetchSettings.production()))
                .isFalse();
        assertThat(IpValidator.isAllowed(ip("::1"), FetchSettings.production())).isFalse();
    }

    @Test
    void allows_loopback_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("127.0.0.1"), FetchSettings.devMode())).isTrue();
        assertThat(IpValidator.isAllowed(ip("::1"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // Private networks
    // -----------------------------------------------------------------------

    @Test
    void blocks_privateNetworks_inProduction() {
        assertThat(IpValidator.isAllowed(ip("10.0.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("10.255.255.255"), FetchSettings.production()))
                .isFalse();
        assertThat(IpValidator.isAllowed(ip("172.16.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("172.31.255.255"), FetchSettings.production()))
                .isFalse();
        assertThat(IpValidator.isAllowed(ip("192.168.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("192.168.255.255"), FetchSettings.production()))
                .isFalse();
    }

    @Test
    void allows_privateNetworks_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("10.0.0.1"), FetchSettings.devMode())).isTrue();
        assertThat(IpValidator.isAllowed(ip("172.16.0.1"), FetchSettings.devMode())).isTrue();
        assertThat(IpValidator.isAllowed(ip("192.168.0.1"), FetchSettings.devMode())).isTrue();
    }

    @Test
    void blocks_cgn_100_64_0_0_per_10() {
        assertThat(IpValidator.isAllowed(ip("100.64.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("100.127.255.255"), FetchSettings.production()))
                .isFalse();
        // 100.128.0.1 is NOT in 100.64/10
        assertThat(IpValidator.isAllowed(ip("100.128.0.1"), FetchSettings.production())).isTrue();
    }

    // -----------------------------------------------------------------------
    // IPv6 embedded IPv4
    // -----------------------------------------------------------------------

    @Test
    void blocks_ipv4Mapped_privateIp() {
        // ::ffff:192.168.1.1 → embedded IPv4 = 192.168.1.1 (private)
        assertThat(IpValidator.isAllowed(ip("::ffff:192.168.1.1"), FetchSettings.production()))
                .isFalse();
    }

    @Test
    void blocks_ipv4Mapped_cloudMetadata() {
        // ::ffff:169.254.169.254 → always blocked
        assertThat(IpValidator.isAllowed(ip("::ffff:169.254.169.254"), FetchSettings.devMode()))
                .isFalse();
    }

    @Test
    void blocks_6to4_privatePrefix() {
        // 2002:c0a8:0101:: → embedded IPv4 = 192.168.1.1
        assertThat(IpValidator.isAllowed(ip("2002:c0a8:0101::"), FetchSettings.production()))
                .isFalse();
    }

    @Test
    void blocks_6to4_cloudMetadataPrefix() {
        // 2002:a9fe:a9fe:: → embedded = 169.254.169.254 (always blocked)
        assertThat(IpValidator.isAllowed(ip("2002:a9fe:a9fe::"), FetchSettings.devMode()))
                .isFalse();
    }

    // -----------------------------------------------------------------------
    // Public IPs — always allowed
    // -----------------------------------------------------------------------

    @Test
    void allows_publicIpv4() {
        assertThat(IpValidator.isAllowed(ip("8.8.8.8"), FetchSettings.production())).isTrue();
        assertThat(IpValidator.isAllowed(ip("1.1.1.1"), FetchSettings.production())).isTrue();
        assertThat(IpValidator.isAllowed(ip("52.0.0.1"), FetchSettings.production())).isTrue();
    }

    @Test
    void allows_publicIpv6() {
        assertThat(IpValidator.isAllowed(ip("2001:4860:4860::8888"), FetchSettings.production()))
                .isTrue();
    }

    // Edge: 172.15.x.x is NOT in 172.16/12
    @Test
    void allows_172_15_outsidePrivateRange() {
        assertThat(IpValidator.isAllowed(ip("172.15.255.255"), FetchSettings.production()))
                .isTrue();
    }

    // Edge: 172.32.x.x is NOT in 172.16/12
    @Test
    void allows_172_32_outsidePrivateRange() {
        assertThat(IpValidator.isAllowed(ip("172.32.0.1"), FetchSettings.production())).isTrue();
    }

    // -----------------------------------------------------------------------
    // IETF Protocol Assignments 192.0.0.0/24
    // -----------------------------------------------------------------------

    @Test
    void blocks_ietfProtocolAssignments_inProduction() {
        assertThat(IpValidator.isAllowed(ip("192.0.0.1"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("192.0.0.255"), FetchSettings.production())).isFalse();
    }

    @Test
    void allows_ietfProtocolAssignments_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("192.0.0.1"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // Unspecified 0.0.0.0/8
    // -----------------------------------------------------------------------

    @Test
    void blocks_unspecified_ipv4_inProduction() {
        assertThat(IpValidator.isAllowed(ip("0.0.0.0"), FetchSettings.production())).isFalse();
        assertThat(IpValidator.isAllowed(ip("0.1.2.3"), FetchSettings.production())).isFalse();
    }

    @Test
    void allows_unspecified_ipv4_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("0.0.0.1"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // CGN in dev mode
    // -----------------------------------------------------------------------

    @Test
    void allows_cgn_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("100.64.0.1"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // Teredo 2001:0000::/32 — embedded IPv4 validation
    // -----------------------------------------------------------------------

    @Test
    void blocks_teredo_withPrivateEmbeddedIp_inProduction() {
        // Embedded client IPv4 = 10.0.0.1 → bytes XOR 0xFF = [0xF5,0xFF,0xFF,0xFE]
        // Teredo: 2001:0000:0000:0000:0000:0000:f5ff:fffe
        assertThat(IpValidator.isAllowed(ip("2001::f5ff:fffe"), FetchSettings.production()))
                .isFalse();
    }

    @Test
    void allows_teredo_withPublicEmbeddedIp_inProduction() {
        // Embedded client IPv4 = 8.8.8.8 → bytes XOR 0xFF = [0xF7,0xF7,0xF7,0xF7]
        // Teredo: 2001:0000:0000:0000:0000:0000:f7f7:f7f7
        assertThat(IpValidator.isAllowed(ip("2001::f7f7:f7f7"), FetchSettings.production()))
                .isTrue();
    }

    // -----------------------------------------------------------------------
    // IPv6 unspecified ::
    // -----------------------------------------------------------------------

    @Test
    void blocks_ipv6Unspecified_inProduction() {
        // :: is all-zeros; treated as loopback-equivalent, blocked in production
        assertThat(IpValidator.isAllowed(ip("::"), FetchSettings.production())).isFalse();
    }

    @Test
    void allows_ipv6Unspecified_inDevMode() {
        assertThat(IpValidator.isAllowed(ip("::"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // IPv4-mapped public IP
    // -----------------------------------------------------------------------

    @Test
    void allows_ipv4Mapped_publicIp_inProduction() {
        // ::ffff:8.8.8.8 → embedded IPv4 = 8.8.8.8 (public) → allowed
        assertThat(IpValidator.isAllowed(ip("::ffff:8.8.8.8"), FetchSettings.production()))
                .isTrue();
    }

    // -----------------------------------------------------------------------
    // 6to4 with public embedded IPv4
    // -----------------------------------------------------------------------

    @Test
    void allows_6to4_withPublicIp_inProduction() {
        // 2002:0808:0808:: → embedded IPv4 bytes 2-5 = [8,8,8,8] = 8.8.8.8 (public)
        assertThat(IpValidator.isAllowed(ip("2002:808:808::"), FetchSettings.production()))
                .isTrue();
    }

    @Test
    void allows_6to4_withPrivateIp_inDevMode() {
        // 2002:c0a8:0101:: → embedded = 192.168.1.1 → private, allowed in devMode
        assertThat(IpValidator.isAllowed(ip("2002:c0a8:101::"), FetchSettings.devMode())).isTrue();
    }

    // -----------------------------------------------------------------------
    // Public IPv6 in dev mode
    // -----------------------------------------------------------------------

    @Test
    void allows_publicIpv6_inDevMode() {
        // Exercises the !settings.ssrfProtection() short-circuit for IPv6
        assertThat(IpValidator.isAllowed(ip("2001:4860:4860::8888"), FetchSettings.devMode()))
                .isTrue();
    }
}
