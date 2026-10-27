package com.verithreat.ioc.normalize;

import java.net.IDN;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Normalización de indicadores, idéntica a {@code loaders.normalize_value} de Python y a lo que exige
 * db/schema.sql (CHECK normalized_value). Las dos implementaciones se prueban con db/normalization_cases.json.
 */
public final class Normalizer {

    public static final Set<String> TYPES = Set.of("sha256", "md5", "sha1", "domain", "url", "ip", "cidr");

    private static final Map<String, Integer> HEX_LENGTH = Map.of("sha256", 64, "sha1", 40, "md5", 32);
    private static final Pattern HEX = Pattern.compile("[0-9a-f]+");
    private static final Pattern DOMAIN = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\\.)+[a-z0-9-]{2,63}$");
    private static final Pattern URL = Pattern.compile("^[a-z][a-z0-9+.-]*://\\S+$",
            Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CHARACTER_CLASS);
    // IPv4 sin ceros a la izquierda (Python ipaddress rechaza «010.1.1.1»)
    private static final String OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
    private static final Pattern IPV4 = Pattern.compile("^" + OCTET + "(\\." + OCTET + "){3}$");
    private static final Pattern IPV6_CHARS = Pattern.compile("^[0-9a-fA-F:.]+$");

    private Normalizer() {
    }

    /** Valor normalizado; lanza {@link InvalidIndicatorException} si no es válido para su tipo. */
    public static String normalize(String type, String value) {
        String v = value == null ? "" : value.strip();
        if (v.isEmpty()) {
            throw new InvalidIndicatorException("empty value");
        }
        if (type == null || !TYPES.contains(type)) {
            throw new InvalidIndicatorException("unknown type: " + type);
        }
        return switch (type) {
            case "sha256", "sha1", "md5" -> hash(type, v);
            case "domain" -> domain(v, value);
            case "url" -> url(v, value);
            case "ip" -> ip(v, value);
            case "cidr" -> cidr(v, value);
            default -> throw new InvalidIndicatorException("unknown type: " + type);
        };
    }

    private static String hash(String type, String v) {
        String h = v.toLowerCase(Locale.ROOT);
        if (h.length() != HEX_LENGTH.get(type) || !HEX.matcher(h).matches()) {
            throw new InvalidIndicatorException("not a " + type + ": " + v);
        }
        return h;
    }

    private static String domain(String v, String original) {
        String d = v.toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        try {
            d = IDN.toASCII(d);
        } catch (IllegalArgumentException e) {
            throw new InvalidIndicatorException("invalid domain: " + original);
        }
        if (!DOMAIN.matcher(d).matches()) {
            throw new InvalidIndicatorException("invalid domain: " + original);
        }
        return d;
    }

    private static String url(String v, String original) {
        if (!URL.matcher(v).matches()) {
            throw new InvalidIndicatorException("invalid url: " + original);
        }
        return v;
    }

    private static String ip(String v, String original) {
        if (v.contains("%")) {
            throw new InvalidIndicatorException("scoped IPv6 not accepted: " + original);
        }
        if (!v.contains(":")) {
            if (!IPV4.matcher(v).matches()) {
                throw new InvalidIndicatorException("invalid ip: " + original);
            }
            return v;
        }
        byte[] bytes = parseIpv6(v, original);
        return formatIpv6(bytes);
    }

    private static String cidr(String v, String original) {
        String[] parts = v.split("/", -1);
        if (parts.length > 2) {
            throw new InvalidIndicatorException("invalid cidr: " + original);
        }
        boolean v6 = parts[0].contains(":");
        byte[] addr;
        if (v6) {
            addr = parseIpv6(parts[0], original);
        } else {
            if (!IPV4.matcher(parts[0]).matches()) {
                throw new InvalidIndicatorException("invalid cidr: " + original);
            }
            addr = ipv4Bytes(parts[0]);
        }
        int max = addr.length * 8;
        int prefix = max;
        if (parts.length == 2) {
            if (!parts[1].matches("\\d{1,3}")) {
                throw new InvalidIndicatorException("invalid cidr: " + original);
            }
            prefix = Integer.parseInt(parts[1]);
            if (prefix > max) {
                throw new InvalidIndicatorException("invalid cidr: " + original);
            }
        }
        // Como Python ip_network(strict=True): los bits de host tienen que ser cero
        for (int bit = prefix; bit < max; bit++) {
            if ((addr[bit / 8] & (0x80 >> (bit % 8))) != 0) {
                throw new InvalidIndicatorException("invalid cidr (host bits set): " + original);
            }
        }
        String a = v6 ? formatIpv6(addr) : parts[0];
        return a + "/" + prefix;
    }

    private static byte[] parseIpv6(String v, String original) {
        // Solo literales: con caracteres hexadecimales, «:» y «.», InetAddress no hace ninguna consulta DNS
        if (!IPV6_CHARS.matcher(v).matches()) {
            throw new InvalidIndicatorException("invalid ip: " + original);
        }
        InetAddress a;
        try {
            a = InetAddress.getByName(v);
        } catch (UnknownHostException e) {
            throw new InvalidIndicatorException("invalid ip: " + original);
        }
        if (a instanceof Inet4Address) { // ::ffff:a.b.c.d: Java lo convierte en IPv4; Python lo rechaza
            throw new InvalidIndicatorException("IPv4-mapped IPv6 not accepted, use the IPv4 address: " + original);
        }
        if (!(a instanceof Inet6Address)) {
            throw new InvalidIndicatorException("invalid ip: " + original);
        }
        return a.getAddress();
    }

    private static byte[] ipv4Bytes(String v) {
        String[] o = v.split("\\.");
        byte[] b = new byte[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (byte) Integer.parseInt(o[i]);
        }
        return b;
    }

    /** Forma comprimida RFC 5952, como Python ipaddress: la racha de ceros más larga (≥ 2 grupos; la primera si empatan). */
    static String formatIpv6(byte[] b) {
        int[] h = new int[8];
        for (int i = 0; i < 8; i++) {
            h[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
        }
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (h[i] != 0) {
                i++;
                continue;
            }
            int j = i;
            while (j < 8 && h[j] == 0) {
                j++;
            }
            if (j - i > bestLen) {
                bestStart = i;
                bestLen = j - i;
            }
            i = j;
        }
        if (bestLen < 2) {
            bestStart = -1;
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i == bestStart) {
                sb.append("::");
                i += bestLen - 1;
                continue;
            }
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != ':') {
                sb.append(':');
            }
            sb.append(Integer.toHexString(h[i]));
        }
        return sb.toString();
    }
}
