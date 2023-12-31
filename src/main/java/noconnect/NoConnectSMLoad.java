/*
 * Licensed under the Open Software License version 3.0
 */

package noconnect;

import cpw.mods.modlauncher.api.IEnvironment;
import cpw.mods.modlauncher.api.ITransformationService;
import cpw.mods.modlauncher.api.ITransformer;
import joptsimple.util.PathConverter;
import joptsimple.util.PathProperties;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public final class NoConnectSMLoad implements ITransformationService {
    private static final Logger LOGGER = LogManager.getLogger();

    @Nonnull
    @Override
    public String name() {
        return "noconnect";
    }

    @Override
    public void initialize(@Nonnull IEnvironment environment) {
        // noop
    }

    @Override
    public void beginScanning(@Nonnull IEnvironment environment) {
        // noop
    }

    @Override
    @ParametersAreNonnullByDefault
    public void onLoad(IEnvironment env, Set<String> otherServices) {

        SecurityManager sm = System.getSecurityManager();
        if (System.getSecurityManager() != null) {
            LOGGER.error("Existing Security Manager is detected! {}", sm.toString());
            throw new SecurityException("Existing Security Manager is detected! " + sm.toString());
        }

        String smProp = AccessController.doPrivileged(
                (PrivilegedAction<String>) () -> System.getProperty("java.security.manager"));
        if ("disallow".equals(smProp)) {
            throw new IllegalStateException("Unable to set Security Manager at runtime, details at JDK-8203316");
        }

        LOGGER.info("Loading NoConnect with configuration");
        // Path property = Launcher.INSTANCE.environment().getProperty(Environment.Keys.GAMEDIR.get()).get();
        // Environment.Keys.GAMEDIR#get is not yet fully initialised with game directory, will crash when used.
        // Idea from ArgumentHandler#setArgs, which obtain the game directory
        Path launchDir = new PathConverter(PathProperties.DIRECTORY_EXISTING).convert(""); // get current dir
        // LOGGER.info("Launch Dir is: {}", launchDir.toAbsolutePath());
        Path configDir = launchDir.resolve("config");
        try {
            if (Files.notExists(configDir)) {
                Files.createDirectory(configDir);
            }
        } catch (IOException | SecurityException e) {
            LOGGER.warn("Unable to create config folder", e);
        }
        Config.loadConfig(configDir.resolve("noconnect.toml"));
        if (!Config.isEnabled()) {
            LOGGER.warn("No Connect is disabled! It will not load.");
            return;
        }

        LOGGER.debug("Installing NoConnect...");
        LOGGER.trace("BEFORE {}", () -> this.getClass().getProtectionDomain());
        LOGGER.trace("BEFORE {}", () -> this.getClass().getProtectionDomain().getClassLoader());

        System.setSecurityManager(new URLSecMgr());
        LOGGER.trace("AFTER {}", () -> this.getClass().getProtectionDomain());
        LOGGER.trace("AFTER {}", () -> this.getClass().getProtectionDomain().getClassLoader());
        LOGGER.info("Successfully initialized NoConnect");

    }

    @Nonnull
    @Override
    @SuppressWarnings("rawtypes")
    public List<ITransformer> transformers() {
        return Collections.emptyList(); // noop
    }

}
