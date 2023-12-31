/*
 * Licensed under the Open Software License version 3.0
 */

package noconnect;

import com.google.common.net.InetAddresses;
import com.google.common.net.InternetDomainName;
import it.unimi.dsi.fastutil.objects.Object2ObjectLinkedOpenHashMap;
import noconnect.Config.LogType;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.MarkerManager;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.filter.MarkerFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLPermission;
import java.net.UnknownHostException;
import java.security.Permission;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Map;
import java.util.stream.Stream;

final class URLSecMgr extends SecurityManager {
    private static final Logger LOGGER = LogManager.getLogger("NoConnect");

    private static final Marker ALLOW_MARKER = MarkerManager.getMarker("NC_ALLOW");
    private static final Marker REJECT_MARKER = MarkerManager.getMarker("NC_REJECT");
    private static final Marker URL_MARKER = MarkerManager.getMarker("NC_URL");
    private static final Marker RESOLVE_MARKER = MarkerManager.getMarker("NC_RESOLVE");
    private static final Marker SOCKET_MARKER = MarkerManager.getMarker("NC_SOCKET");
    private static final Marker INTERFACE_MARKER = MarkerManager.getMarker("NC_INTERFACE");

    private static final Map<String, String> IP_CACHE = new Object2ObjectLinkedOpenHashMap<>();
    private static final String hostName = getHostName();
    private static final HashSet<InetAddress> hostAddress = getAllHostAddress();

    private final ThreadLocal<Boolean> isRecursive = ThreadLocal.withInitial(() -> Boolean.FALSE);

    public URLSecMgr() {
        super();

        LoggerConfig logCfg = ((LoggerContext) LogManager.getContext(false))
                .getConfiguration()
                .getLoggerConfig("NoConnect");

        LogType logType = Config.getMode();

        if (EnumSet.of(LogType.NONE).contains(logType)) {
            logCfg.addFilter(MarkerFilter.createFilter(ALLOW_MARKER.getName(), Filter.Result.DENY, Filter.Result.NEUTRAL));
            logCfg.addFilter(MarkerFilter.createFilter(REJECT_MARKER.getName(), Filter.Result.DENY, Filter.Result.NEUTRAL));
        }
        if (EnumSet.of(LogType.NONE, LogType.MINIMAL).contains(logType)) {
            logCfg.addFilter(MarkerFilter.createFilter(URL_MARKER.getName(), Filter.Result.DENY, Filter.Result.NEUTRAL));
        }
        if (EnumSet.of(LogType.NONE, LogType.MINIMAL, LogType.INFO).contains(logType)) {
            logCfg.addFilter(MarkerFilter.createFilter(RESOLVE_MARKER.getName(), Filter.Result.DENY, Filter.Result.NEUTRAL));
            logCfg.addFilter(MarkerFilter.createFilter(SOCKET_MARKER.getName(), Filter.Result.DENY, Filter.Result.NEUTRAL));
        }
    }

    @Override
    public void checkConnect(String host, int port) {
        processHost(host, port);
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        processHost(host, port);
    }

    @Override
    public void checkPermission(Permission perm) {
        processPerm(perm);
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        processPerm(perm);
    }

    @Override
    public void checkPackageAccess(String pkg) {
        // noop for performance reason
    }

    // Start of handling
    @SuppressWarnings("UnstableApiUsage")
    private void processHost(String host, int port) {
        Thread.UncaughtExceptionHandler originalErrHandler = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler(URLSecMgr::onUnknownError);

        boolean isIP = InetAddresses.isInetAddress(host);
        InetAddress addr = isIP ? InetAddresses.forString(host) : null;

        if ((isIP && addr.isLoopbackAddress()) || "localhost".equals(host) || host.equals(hostName)) {
            LOGGER.trace(SOCKET_MARKER, "Ignoring localhost {} {}", () -> host, () -> port);
            return;
        }

        // undetermined port
        boolean portRequest = (port == -1);

        // allow java 11 HttpClient to work. It required host address for internal processing?
        if (portRequest && isIP) {
            final InetAddress ipAddr = InetAddresses.forString(host);
            LOGGER.trace(SOCKET_MARKER, "IP Type: {}", ipAddr.getClass().toString());

            boolean matchHostAddress = hostAddress.contains(ipAddr);
            LOGGER.trace(SOCKET_MARKER, "Host: {}, IPAddr: {}, Match, {}", host, ipAddr, matchHostAddress);

            if (matchHostAddress) {
                LOGGER.debug(SOCKET_MARKER, "Allowed current host address {}", host);
                return;
            }
        }


        if (isIP && (IP_CACHE.containsKey(host) || Config.getAllowedIPs().contains(host))) {
            if (portRequest) {
                LOGGER.debug(ALLOW_MARKER, "Allowed IP (request) - {}:{}/{}",
                        host, port, IP_CACHE.getOrDefault(host, "not_cached"));
            } else {
                LOGGER.debug(ALLOW_MARKER, "Allowed IP - {}:{}/{}",
                        host, port, IP_CACHE.getOrDefault(host, "not_cached"));
            }
            return;
        }

        // Thread Allow
        String threadName = Thread.currentThread().getName();
        if (Config.getAllowedThread().stream().anyMatch(threadName::startsWith)) {
            LOGGER.info(ALLOW_MARKER, "Allowed thread: [{}] - {}:{}", threadName, host, port);
            return;
        }

        // Allow hosts
        if (InternetDomainName.isValid(host)/* && InternetDomainName.from(host).hasPublicSuffix()*/) {
            boolean can = Config.getAllowedHosts().stream().anyMatch(s -> NetworkUtil.matchesHostname(host, s));
            if (isRecursiveCall() && can) {
                return;
            }
            if (can) {
                isRecursive.set(Boolean.TRUE);
                try {
                    if (port != -1) {
                        LOGGER.info(ALLOW_MARKER, "Allowed Host - {}:{}", host, port);
                    } else {
                        LOGGER.debug(RESOLVE_MARKER, "Resolve Host - {}:{}", host, port);
                    }
                    addHostToCache(host, port); // getIPFromHost will invoke checkConnect
                    isRecursive.set(Boolean.FALSE);
                } finally {
                    isRecursive.set(Boolean.FALSE);
                }
                return;
            }
        }

        if (Config.isAuditMode()) {
            LOGGER.info("Audit Mode, Allowing host: {}:{}", host, port);
            return;
        }

        if (port == 53 && Config.allowAllDns()) {
            LOGGER.debug(SOCKET_MARKER, "Allow DNS {}:{}", host, port);
            return;
        }

        if (!portRequest) {
            LOGGER.info(REJECT_MARKER, "Denied - {}:{}", host, port);
        } else {
            LOGGER.debug(REJECT_MARKER, "Denied (request) - {}:{}", host, port);
        }

        Thread.setDefaultUncaughtExceptionHandler(originalErrHandler);

        IOException ex = new IOException("Denied - " + host + ":" + port);
        ExceptionUtils.rethrow(ex); // checked exception without declaring
    }

    private void addHostToCache(String host, int port) {
        LOGGER.trace("Resolving Host - {}:{}", host, port);
        InetAddress[] ip = NetworkUtil.getIPFromHost(host); // will invoke checkConnect
        if (ip != null) {
            Stream.of(ip).forEach(addr -> {
                if (IP_CACHE.put(addr.getHostAddress(), host) == null) {
                    LOGGER.debug("Allowed {}/{} into cache", host, addr.getHostAddress());
                }
            });
        }
    }

    private static String getHostName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            LOGGER.error(e);
        }
        return "localhost";
    }

    private static HashSet<InetAddress> getAllHostAddress() {
        HashSet<InetAddress> hostAddresses = new HashSet<>();
        try {
            final InetAddress localHost = InetAddress.getLocalHost(); // current host address
            final String hostName = localHost.getHostName();

            final InetAddress[] allHostsAddress = InetAddress.getAllByName(hostName);
            Collections.addAll(hostAddresses, allHostsAddress);

            return hostAddresses;
        } catch (IOException e) {
            LOGGER.error(INTERFACE_MARKER, "Error while getting all host address", e);
            hostAddresses.add(InetAddress.getLoopbackAddress());
            return hostAddresses;
        }
    }

    private boolean isRecursiveCall() {
        return isRecursive.get().equals(Boolean.TRUE);
    }

    private void processPerm(Permission perm) {
        if (perm instanceof URLPermission) {
            try {
                URL url = new URL(perm.getName());
                Class<?>[] clsContext = getClassContext();
                if (Config.isLogCaller()) {
                    if ("https".equals(url.getProtocol())) {
                        getHTTPSCaller(clsContext);
                    } else if ("http".equals(url.getProtocol())) {
                        getHTTPCaller(clsContext);
                    } else {
                        getGenericCaller(clsContext);
                    }
                }

                boolean isWeb = "https".equals(url.getProtocol()) || "http".equals(url.getProtocol());
                if (isWeb && url.getPort() == -1 /*Default Port*/) {
                    LOGGER.info(URL_MARKER, "URL: {} Actions: {}", perm.getName(), perm.getActions());
                } else if (isWeb) { // defined port
                    LOGGER.warn(URL_MARKER, "Custom port URL: {} Actions: {}", perm.getName(), perm.getActions());
                } else {
                    LOGGER.warn(URL_MARKER, "Non web URL scheme detected, below URL is not HTTP(S).");
                    LOGGER.warn(URL_MARKER, "URL: {} Actions: {}", perm.getName(), perm.getActions());
                }
                return;
            } catch (MalformedURLException e) {
                LOGGER.fatal(URL_MARKER, "Exception parsing URLPermission, {}", perm.getName());
                LOGGER.fatal(URL_MARKER, "Exception parsing URL, this should never happen!", e);
            }
        }
        if (perm instanceof RuntimePermission && "setSecurityManager".equals(perm.getName())) {
            throw new SecurityException("Attempting to replace NoConnect Security Manager! " + perm.getActions());
        }
    }

    private void getHTTPSCaller(Class<?>[] classContext) {
        /*
         * The last element is the class that called, default get first 4 from caller
         * Ex: class ExampleHTTPSPackage.TargetClass
         *     class Main <-- class that call target
         * */
        boolean hasHTTPS = false;
        int printCount = 4;

        for (int i = 0, count = 0; i < classContext.length && count < printCount; i++) {
            String currentClass = classContext[i].getName();

            if (!hasHTTPS) {
                hasHTTPS = "sun.net.www.protocol.https.HttpsURLConnectionImpl".equals(currentClass);
                continue;
            }
            LOGGER.debug("Possible Caller: {} ", currentClass);
            count++;
        }
    }

    private void getHTTPCaller(Class<?>[] classContext) {
        //same as getHTTPSCaller except for http display
        boolean hasHTTP = false;
        int printCount = 4;
        for (int i = 0, count = 0; (i < classContext.length) && count < printCount; i++) {
            String currentClass = classContext[i].getName();

            if (!hasHTTP) {
                String nextClass = classContext[Math.min(i + 1, classContext.length - 1)].getName();
                boolean targetHTTP = "sun.net.www.protocol.http.HttpURLConnection".equals(currentClass);
                boolean isNextSameHTTP = "sun.net.www.protocol.http.HttpURLConnection".equals(nextClass);
                hasHTTP = targetHTTP && !isNextSameHTTP;
                continue;
            }
            LOGGER.debug("Possible Caller: {} ", currentClass);
            count++;
        }
    }

    private void getGenericCaller(Class<?>[] classContext) {
        LOGGER.warn("Non web URL is requested, unable to get caller, printing all possible caller...");
        for (Class<?> cls : classContext) {
            LOGGER.warn(cls);
        }
    }

    private static void onUnknownError(Thread t, Throwable e) {
        LOGGER.error("Error on: {}", t.getName(), e);
    }

}
