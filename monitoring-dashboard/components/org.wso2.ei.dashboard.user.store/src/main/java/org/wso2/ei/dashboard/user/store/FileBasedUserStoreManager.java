package org.wso2.ei.dashboard.user.store;

import net.consensys.cava.toml.Toml;
import net.consensys.cava.toml.TomlParseResult;
import net.consensys.cava.toml.TomlTable;
import org.wso2.ei.dashboard.user.store.UserStoreManager;
import org.wso2.ei.dashboard.user.store.UserInfo;
import org.wso2.config.mapper.ConfigParser;
import org.wso2.config.mapper.ConfigParserException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FileBasedUserStoreManager implements UserStoreManager {
    private static volatile FileBasedUserStoreManager instance;
    private Map<String, UserInfo> users;

    // Private constructor to prevent instantiation
    private FileBasedUserStoreManager() {
        initialize();
        users = new HashMap<>();
    }

    // Public method to get the instance, with lazy initialization
    public static FileBasedUserStoreManager getInstance() {
        if (instance == null) {
            synchronized (FileBasedUserStoreManager.class) {
                // Double-check pattern
                if (instance == null) {
                    instance = new FileBasedUserStoreManager();
                }
            }
        }
        return instance;
    }

    // Initialize with user data
    private void initialize(Map<String, UserInfo> usersMap) {
        this.users = usersMap;
    }

    private void initialize() {
        // lets have a util module and constants model
        initializeFileBasedUserStore();

    }

    private void initializeFileBasedUserStore() {
        String tomlPath = System.getProperty("dashboard_toml_file_path");
        if (tomlPath != null) {
            String tomlContent = null;
            try {
                tomlContent = Files.readString(Path.of(tomlPath));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            TomlParseResult result = Toml.parse(tomlContent);

            if (result.hasErrors()) {
                result.errors().forEach(error -> System.out.println(error.toString()));
                return;
            }
            TomlTable dashboard = result.getTableOrEmpty("dashboard");
//            List<TomlTable> users = dashboard.get
//            for (TomlTable userTable : users) {
//                String name = userTable.getString("user.name");
//                String password = userTable.getString("user.password");
////                List<String> groups = userTable.getList("groups");
//
//                System.out.println("User: " + name);
//                System.out.println("Password: " + password);
//                System.out.print("Groups: ");
////                groups.forEach(group -> System.out.print(group + " "));
//                System.out.println("\n---------");
//            }
        }
    }

    // Authenticate method and other user store operations
    public boolean authenticate(String username, String password) {
        UserInfo userInfo = users.get(username);
        return userInfo != null && Arrays.equals(userInfo.getPassword(), password.toCharArray());
    }

    // Additional methods...
}
