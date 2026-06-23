package ai.authplane.sdk.core.fetching.ssrf;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;

import ai.authplane.sdk.core.fetching.FetchSettings;

/**
 * Validates that a resolved IP address is permitted under the given FetchSettings.
 *
 * <p>Thread-safe — all methods are stateless.
 */
public final class IpValidator {

    private IpValidator() {}

    /**
     * Returns true if the given IP address is allowed under the settings. Returns false if the IP
     * is blocked.
     *
     * <p>Callers should throw SsrfException when this returns false.
     *
     * @param address a resolved InetAddress (IPv4 or IPv6)
     * @param settings the SSRF configuration
     */
    public static boolean isAllowed(InetAddress address, FetchSettings settings) {
        if (address instanceof Inet6Address ipv6) {
            return isIpv6Allowed(ipv6, settings);
        } else {
            return isIpv4Allowed((Inet4Address) address, settings);
        }
    }

    // -----------------------------------------------------------------------
    // IPv4 validation
    // -----------------------------------------------------------------------

    private static boolean isIpv4Allowed(Inet4Address address, FetchSettings settings) {
        byte[] b = address.getAddress(); // 4 bytes, big-endian

        // Always blocked: link-local 169.254.0.0/16 (cloud metadata)
        if ((b[0] & 0xFF) == 169 && (b[1] & 0xFF) == 254) {
            return false;
        }

        // Always blocked: multicast 224.0.0.0/4
        if ((b[0] & 0xF0) == 224) {
            return false;
        }

        // If SSRF protection is disabled (dev mode), allow everything else.
        if (!settings.ssrfProtection()) {
            return true;
        }

        // Loopback 127.0.0.0/8
        if ((b[0] & 0xFF) == 127) {
            return settings.allowLocalhost();
        }

        // Private 10.0.0.0/8
        if ((b[0] & 0xFF) == 10) {
            return settings.allowPrivateNetworks();
        }

        // Private 172.16.0.0/12  (172.16.x.x – 172.31.x.x)
        if ((b[0] & 0xFF) == 172 && (b[1] & 0xF0) == 16) {
            return settings.allowPrivateNetworks();
        }

        // Private 192.168.0.0/16
        if ((b[0] & 0xFF) == 192 && (b[1] & 0xFF) == 168) {
            return settings.allowPrivateNetworks();
        }

        // RFC 6598 Carrier-Grade NAT 100.64.0.0/10
        if ((b[0] & 0xFF) == 100 && (b[1] & 0xC0) == 64) {
            return settings.allowPrivateNetworks();
        }

        // IETF Protocol Assignments 192.0.0.0/24
        if ((b[0] & 0xFF) == 192 && (b[1] & 0xFF) == 0 && (b[2] & 0xFF) == 0) {
            return settings.allowPrivateNetworks();
        }

        // Unspecified 0.0.0.0/8
        if ((b[0] & 0xFF) == 0) {
            return settings.allowPrivateNetworks();
        }

        return true; // globally routable
    }

    // -----------------------------------------------------------------------
    // IPv6 validation
    // -----------------------------------------------------------------------

    private static boolean isIpv6Allowed(Inet6Address address, FetchSettings settings) {
        byte[] b = address.getAddress(); // 16 bytes, big-endian

        // Always blocked: link-local fe80::/10
        //   First 10 bits are 1111111010 → byte[0]=0xFE, byte[1] high 2 bits = 0b10
        if ((b[0] & 0xFF) == 0xFE && (b[1] & 0xC0) == 0x80) {
            return false;
        }

        // Always blocked: multicast ff00::/8
        if ((b[0] & 0xFF) == 0xFF) {
            return false;
        }

        // IPv4-mapped ::ffff:x.x.x.x — validate the embedded IPv4
        // Detected by: bytes 0-9 are 0, bytes 10-11 are 0xFF 0xFF
        if (isIpv4Mapped(b)) {
            InetAddress embedded = extractIpv4Mapped(b);
            return isAllowed(embedded, settings);
        }

        // 6to4 2002::/16 — bytes 0-1 are 0x20 0x02
        // Embedded IPv4 is at bytes 2-5
        if ((b[0] & 0xFF) == 0x20 && (b[1] & 0xFF) == 0x02) {
            InetAddress embedded = extractIpv4From6to4(b);
            return isAllowed(embedded, settings);
        }

        // Teredo 2001:0000::/32 — bytes 0-3 are 0x20 0x01 0x00 0x00
        // Client IPv4 is at bytes 12-15 XOR'd with 0xFFFFFFFF
        if ((b[0] & 0xFF) == 0x20
                && (b[1] & 0xFF) == 0x01
                && (b[2] & 0xFF) == 0x00
                && (b[3] & 0xFF) == 0x00) {
            InetAddress clientIp = extractIpv4FromTeredo(b);
            return isAllowed(clientIp, settings);
        }

        // If SSRF protection disabled, allow everything else
        if (!settings.ssrfProtection()) {
            return true;
        }

        // Loopback ::1
        if (isIpv6Loopback(b)) {
            return settings.allowLocalhost();
        }

        // Unspecified ::
        if (isIpv6Unspecified(b)) {
            return settings.allowLocalhost();
        }

        return true; // globally routable
    }

    // -----------------------------------------------------------------------
    // IPv6 helper methods
    // -----------------------------------------------------------------------

    private static boolean isIpv4Mapped(byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) return false;
        }
        return (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
    }

    private static InetAddress extractIpv4Mapped(byte[] b) {
        try {
            byte[] v4 = new byte[] {b[12], b[13], b[14], b[15]};
            return InetAddress.getByAddress(v4);
        } catch (Exception e) {
            throw new SsrfException("Failed to extract IPv4-mapped address", e);
        }
    }

    private static InetAddress extractIpv4From6to4(byte[] b) {
        try {
            byte[] v4 = new byte[] {b[2], b[3], b[4], b[5]};
            return InetAddress.getByAddress(v4);
        } catch (Exception e) {
            throw new SsrfException("Failed to extract 6to4 embedded IPv4", e);
        }
    }

    private static InetAddress extractIpv4FromTeredo(byte[] b) {
        // Client IPv4 is in last 4 bytes, XOR'd with 0xFFFFFFFF
        try {
            byte[] v4 =
                    new byte[] {
                        (byte) (b[12] ^ 0xFF),
                        (byte) (b[13] ^ 0xFF),
                        (byte) (b[14] ^ 0xFF),
                        (byte) (b[15] ^ 0xFF)
                    };
            return InetAddress.getByAddress(v4);
        } catch (Exception e) {
            throw new SsrfException("Failed to extract Teredo client IPv4", e);
        }
    }

    private static boolean isIpv6Loopback(byte[] b) {
        for (int i = 0; i < 15; i++) {
            if (b[i] != 0) return false;
        }
        return b[15] == 1;
    }

    private static boolean isIpv6Unspecified(byte[] b) {
        for (byte byt : b) {
            if (byt != 0) return false;
        }
        return true;
    }
}
