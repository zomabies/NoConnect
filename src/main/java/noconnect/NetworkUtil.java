/*
 * Licensed under the Open Software License version 3.0
 */

package noconnect;

import java.net.InetAddress;
import java.net.UnknownHostException;

final class NetworkUtil {

    private NetworkUtil() {
    }

    /*
     * with modification from,
     * https://github.com/square/okhttp/blob/cd722373281202492043f4294fccfe6f691ddc01/okhttp/src/main/kotlin/okhttp3/CertificatePinner.kt#L276
     * */
    public static boolean matchesHostname(String hostname, String pattern) {
        if (pattern.startsWith("*.")) {
            // With * there must be a prefix so include the dot in regionMatches().
            int suffixLength = pattern.length() - 1;
            int prefixLength = hostname.length() - suffixLength;
            return hostname.regionMatches(hostname.length() - suffixLength, pattern, 1, suffixLength) &&
                    /*hostname.lastIndexOf('.', prefixLength - 1) == -1;*/
                    hostname.charAt(prefixLength) == '.'; // allow *. to indicate all wildcard
        } else {
            return hostname.equals(pattern);
        }
    }

    static InetAddress[] getIPFromHost(String host) {
        try {
            return InetAddress.getAllByName(host);
        } catch (UnknownHostException ignored) {
        }
        return null;
    }

}
