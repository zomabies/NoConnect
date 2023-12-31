/*
 * Licensed under the Open Software License version 3.0
 */

package noconnect;

import com.electronwill.nightconfig.core.CommentedConfig;
import com.electronwill.nightconfig.core.ConfigSpec;
import com.electronwill.nightconfig.core.EnumGetMethod;
import com.electronwill.nightconfig.core.UnmodifiableCommentedConfig.CommentNode;
import com.electronwill.nightconfig.core.file.CommentedFileConfig;
import com.electronwill.nightconfig.core.io.IndentStyle;
import com.electronwill.nightconfig.core.io.ParsingException;
import com.electronwill.nightconfig.core.io.WritingMode;
import com.electronwill.nightconfig.toml.TomlFormat;
import com.electronwill.nightconfig.toml.TomlWriter;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static java.util.Arrays.asList;
import static java.util.Collections.unmodifiableList;

final class Config {

    private static CommentedFileConfig config;
    private static final ConfigSpec cfgSpec;
    private static final Logger LOGGER = LogManager.getLogger();
    private static final List<String> ALLOW_HOSTS = unmodifiableList(
            asList("*.minecraft.net", "*.minecraftservices.com", "*.mojang.com"));
    private static final List<String> ALLOW_THREAD = Collections.emptyList();

    private Config() {
    }

    static {
        boolean isPreserved = com.electronwill.nightconfig.core.Config.isInsertionOrderPreserved();
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(true);
        cfgSpec = new ConfigSpec();
        cfgSpec.define("enable", true, o -> o instanceof Boolean);
        cfgSpec.define("allow_dns", true, o -> o instanceof Boolean);
        cfgSpec.defineRestrictedEnum("log_type", LogType.class, asList(LogType.values()), EnumGetMethod.NAME, () -> LogType.INFO);
        cfgSpec.define("audit_mode", false, o -> o instanceof Boolean);
        cfgSpec.define("log_caller", false, o -> o instanceof Boolean);
        cfgSpec.defineList("allowed.hosts", ALLOW_HOSTS, o -> (o instanceof String));
        cfgSpec.defineList("allowed.ip", Collections.emptyList(), o -> (o instanceof String));
        cfgSpec.defineList("allowed.thread", ALLOW_THREAD, o -> (o instanceof String));
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(isPreserved);
    }

    static void loadConfig(Path configPath) {
        boolean isPreserved = com.electronwill.nightconfig.core.Config.isInsertionOrderPreserved();
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(true);
        config = CommentedFileConfig
                .builder(configPath, TomlFormat.instance())
                .preserveInsertionOrder()
                .sync()
                .build();

        try {
            config.load();
        } catch (ParsingException e) {
            LOGGER.error("Encounter invalid config file:\n", e);
            makeConfigBackup(true);
            config.clear();
            saveConfig(config);
            config.load();
        }

        if (!cfgSpec.isCorrect(config)) {
            LOGGER.warn("Correcting Config File!");
            makeConfigBackup(false);
            cfgSpec.correct(config, (action, path, incorrectValue, correctedValue) -> {
                LOGGER.warn("Action:{} Path:{} Wrong:{} Corrected:{}", action, path, incorrectValue, correctedValue);
            });
            config.putAllComments(generateConfigComment());
        }

        saveConfig(config);
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(isPreserved);
    }

    static List<String> getAllowedHosts() {
        return config.getOrElse("allowed.hosts", ALLOW_HOSTS);
    }

    static List<String> getAllowedIPs() {
        return config.getOrElse("allowed.ips", Collections::emptyList);
    }

    static List<String> getAllowedThread() {
        return config.getOrElse("allowed.thread", ALLOW_THREAD);
    }

    static LogType getMode() {
        return config.getEnumOrElse("log_type", LogType.INFO, EnumGetMethod.NAME);
    }

    static boolean isAuditMode() {
        return config.getOrElse("audit_mode", false);
    }

    static boolean isLogCaller() {
        return config.getOrElse("log_caller", true);
    }

    static boolean isEnabled() {
        return config.getOrElse("enabled", true);
    }

    static boolean allowAllDns() {
        return config.getOrElse("allow_dns", true);
    }

    private static Map<String, CommentNode> generateConfigComment() {
        boolean isPreserved = com.electronwill.nightconfig.core.Config.isInsertionOrderPreserved();
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(true);
        CommentedConfig cfgMain = CommentedConfig.inMemory();
        com.electronwill.nightconfig.core.Config.setInsertionOrderPreserved(isPreserved);

        cfgMain.set("enable", "");
        cfgMain.setComment("enable", "Enables NoConnect. \n" +
                "Except in the \"allowed\" category, other connections are blocked");

        cfgMain.set("allow_dns", "");
        cfgMain.setComment("allow_dns", "Allow all DNS queries (port 53).\n" +
                "This allows any resolver address, even it is not in any allowed list.\n" +
                "May break some query if disabled; ie, SRV");

        cfgMain.set("log_type", "");
        cfgMain.setComment("log_type", "Logging visibility. \n" +
                "Valid options are MINIMAL, INFO, VERBOSE, NONE");

        cfgMain.set("audit_mode", "");
        cfgMain.setComment("audit_mode", "Allow all connections without disabling.\n" +
                "Useful for troubleshooting");

        cfgMain.set("log_caller", "");
        cfgMain.setComment("log_caller", "Show possible classes that made connection.");

        CommentedConfig cfgAllowed = cfgMain.createSubConfig();

        cfgAllowed.set("hosts", "");
        cfgAllowed.setComment("hosts", "Hosts that are allowed to connect. \n" +
                "Mojang/Minecraft host are allowed by default. \n" +
                "Use \"*.\" to allow wildcard match of host; *.example.com allows test.example.com");

        cfgAllowed.set("ip", "");
        cfgAllowed.setComment("ip", "The IP that are allowed to connect. \n" +
                "Example of IP: 127.0.0.1");

        cfgAllowed.set("thread", "");
        cfgAllowed.setComment("thread", "Thread that exempted from blocking. \n" +
                "When excluding thread, you can allow multiple similar threads, \n" +
                "Example: Chunk Thread #1, Chunk Thread #2, only add \"Chunk Thread\" here.");

        cfgMain.add("allowed", cfgAllowed);
        cfgMain.setComment("allowed", "Values below is exempted from blocking,\n" +
                "Please check the Host/IP before adding to this category.\n" +
                "NOTE -- Invalid entries will reset the configuration to default values!");
        return cfgMain.getComments();
    }

    private static void saveConfig(CommentedFileConfig cfg) {
        TomlWriter writer = new TomlWriter();
        writer.setIndent(IndentStyle.SPACES_4);
        writer.setIndentArrayElementsPredicate(a -> a.size() >= 1);
        writer.write(cfg, cfg.getFile(), WritingMode.REPLACE);
    }

    private static void makeConfigBackup(boolean isException) {
        if (!isException && config.isEmpty()) {
            LOGGER.info("Not Performing backup, the config is empty.");
            return;
        }
        String suffix = isException ? "-ERROR.toml" : "-BKP.toml";
        Path path = config.getNioPath();
        String fileName = FilenameUtils.getBaseName(path.toFile().getName());
        try {
            LOGGER.info("Performing backup of NoConnect! Backup file appended with {}{}", fileName, suffix);
            Files.copy(path, path.resolveSibling(fileName + suffix), StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            LOGGER.error("Unable to make backup of NoConnect!", e);
        }
    }

    enum LogType {
        MINIMAL, INFO, VERBOSE, NONE
    }

}
