package org.wso2.dashboard.security.user.core.file;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.UserInfo;
import org.wso2.dashboard.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.core.util.MicroIntegratorBaseUtils;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.common.AbstractUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
import org.wso2.securevault.SecretResolverFactory;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.*;

public class FileBasedUserStoreManager extends AbstractUserStoreManager implements UserStoreManager {
    private static Log log = LogFactory.getLog(FileBasedUserStoreManager.class);
    private static final FileBasedUserStoreManager userStoreManager = new FileBasedUserStoreManager();
    private static final String USER_MGT_CONFIG_FILE = "user-mgt.xml";
    private static final String REALM = "Realm";
    private static final String FILE_USER_STORE = "FileUserStore";
    private static final String USERS = "users";
    private static final String USER = "user";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String IS_ADMIN = "isAdmin";
    private static Map<String, UserInfo> userMap;

    private FileBasedUserStoreManager() {
        initializeUserStore();
    }

    private static void initializeUserStore() {
        if (log.isDebugEnabled()) {
            log.debug("Initializing FileBasedUserStoreManager");
        }
//        todo delete this
        log.info("Initializing FileBasedUserStoreManager");
        OMElement documentElement = null;
        File userMgtConfigXml = new File(System.getProperty("carbon.config.dir.path"), USER_MGT_CONFIG_FILE);

        try (InputStream fileInputStream = Files.newInputStream(userMgtConfigXml.toPath())) {
//            InputStream inputStream = MicroIntegratorBaseUtils.replaceSystemVariablesInXml(fileInputStream);
            StAXOMBuilder builder = new StAXOMBuilder(fileInputStream);
            documentElement = builder.getDocumentElement();
        } catch (IOException | XMLStreamException e) {
            log.error("Error occurred while reading user-mgt.xml", e);
        }
        if (documentElement == null) {
            log.error("Error occurred while reading user-mgt.xml. Document element is null.");
            return;
        }
//        secretResolver = SecretResolverFactory.create(documentElement, true);
        OMElement realmElement = (OMElement) documentElement.getFirstChildWithName(new QName(REALM));
        if (Objects.nonNull(realmElement)) {
            OMElement fileUserStore = (OMElement) realmElement.getFirstChildWithName(new QName(FILE_USER_STORE));
            if (Objects.nonNull(fileUserStore)) {
                userMap = populateUsers(fileUserStore.getFirstChildWithName(new QName(USERS)));
            } else {
                log.error("Error parsing the file based user store. File user store element not found in user-mgt.xml");
            }
        } else {
            log.error("Error parsing the file based user store. Realm element not found in user-mgt.xml");
        }
    }

    private static Map<String, UserInfo> populateUsers(OMElement users) {
        HashMap<String, UserInfo> userMap = new HashMap<>();
        if (users != null) {
            Iterator<OMElement> usersIterator = users.getChildrenWithName(new QName(USER));
            if (usersIterator != null) {
                while (usersIterator.hasNext()) {
                    OMElement userElement = usersIterator.next();
                    OMElement userNameElement = userElement.getFirstChildWithName(new QName(USERNAME));
                    OMElement passwordElement = userElement.getFirstChildWithName(new QName(PASSWORD));
                    OMElement isAdminElement = userElement.getFirstChildWithName(new QName(IS_ADMIN));

                    if (userNameElement != null && passwordElement != null) {
                        String userName = userNameElement.getText();
                        if (userMap.containsKey(userName)) {
                            System.out.println("Error parsing the file based user store. User: " + userName + " defined "
                                    + "more than once.");
                        }
                        boolean isAdmin = false;
                        if (isAdminElement != null) {
                            isAdmin = Boolean.parseBoolean(isAdminElement.getText().trim());
                        }
                        userMap.put(userName, new UserInfo(passwordElement.getText().toCharArray(), isAdmin));
                    }
                }
            }
        }
        return userMap;
    }


    /**
     * Method to retrieve FileBasedUserStoreManager
     *
     * @return FileBasedUserStoreManager
     */
    public static FileBasedUserStoreManager getUserStoreManager() {
        return userStoreManager;
    }

    @Override
    public boolean doAuthenticate(String username, String password) {
        UserInfo userInfo = userMap.get(username);
        if (userInfo != null) {
            return new String(userInfo.getPassword()).equals(password);
        }
        return false;
    }

    @Override
    public String[] doGetRoleListOfUser(String username) throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean isAdmin(String username) throws UserStoreException {
        return userMap.get(username).isAdmin();
    }


//    private void loadUserStore() {
//        String userStoreFilePath =
//                System.getProperty("carbon.config.dir.path").concat(File.separator).concat("user-store.json");
//        File file = new File(userStoreFilePath);
//
//        try {
//            ObjectMapper objectMapper = new ObjectMapper();
//            JsonNode root = objectMapper.readTree(file);
//            JsonNode usersNode = root.path("user_store").path("users");
//
//            if (usersNode.isArray()) {
//                for (JsonNode userNode : usersNode) {
//                    String username = userNode.path("username").asText();
//                    String password = userNode.path("password").asText();
//                    List<String> groups = new ArrayList<>();
//
//                    if (userNode.has("groups")) {
//                        for (JsonNode groupNode : userNode.path("groups")) {
//                            groups.add(groupNode.asText());
//                        }
//                    }
//
//                    userMap.put(username, new UserInfo(password.toCharArray(), groups));
//                }
//            }
//        } catch (IOException e) {
////            todo revisit this
//            throw new RuntimeException(e);
//        }
//    }

//    public List<String> getUserGroups(String username) {
//        UserInfo userInfo = userMap.get(username);
//        if (userInfo != null) {
//            return userInfo.getGroups();
//        }
//        return new ArrayList<>();
//    }

    @Override
    public String[] getProfileNames(String s) throws UserStoreException {
        return new String[0];
    }

    @Override
    public String[] getAllProfileNames() throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean isReadOnly() throws UserStoreException {
        return false;
    }

    @Override
    public int getUserId(String s) throws UserStoreException {
        return 0;
    }

    @Override
    public int getTenantId(String s) throws UserStoreException {
        return 0;
    }

    @Override
    public int getTenantId() throws UserStoreException {
        return 0;
    }

    @Override
    public Map<String, String> getProperties(org.wso2.micro.integrator.security.user.api.Tenant tenant) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        return null;
    }

    @Override
    public boolean isMultipleProfilesAllowed() {
        return false;
    }

    @Override
    public void addRememberMe(String s, String s1) throws org.wso2.micro.integrator.security.user.api.UserStoreException {

    }

    @Override
    public boolean isValidRememberMeToken(String s, String s1) throws org.wso2.micro.integrator.security.user.api.UserStoreException {
        return false;
    }

    @Override
    public Properties getDefaultUserStoreProperties() {
        return null;
    }

    @Override
    public Map<String, String> getProperties(Tenant tenant) throws UserStoreException {
        return null;
    }

    @Override
    public boolean isBulkImportSupported() throws UserStoreException {
        return false;
    }

    @Override
    public RealmConfiguration getRealmConfiguration() {
        return null;
    }

    @Override
    protected Map<String, String> getUserPropertyValues(String s, String[] strings, String s1) throws UserStoreException {
        return null;
    }

    @Override
    protected boolean doCheckExistingRole(String s) throws UserStoreException {
        return false;
    }

    @Override
    protected RoleContext createRoleContext(String s) throws UserStoreException {
        return null;
    }

    @Override
    protected boolean doCheckExistingUser(String s) throws UserStoreException {
        return false;
    }

    @Override
    protected String[] getUserListFromProperties(String s, String s1, String s2) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected boolean doAuthenticate(String s, Object o) throws UserStoreException {
        return false;
    }

    @Override
    protected void doAddUser(String s, Object o, String[] strings, Map<String, String> map, String s1, boolean b) throws UserStoreException {

    }

    @Override
    protected void doUpdateCredential(String s, Object o, Object o1) throws UserStoreException {

    }

    @Override
    protected void doUpdateCredentialByAdmin(String s, Object o) throws UserStoreException {

    }

    @Override
    protected void doDeleteUser(String s) throws UserStoreException {

    }

    @Override
    protected void doSetUserClaimValue(String s, String s1, String s2, String s3) throws UserStoreException {

    }

    @Override
    protected void doSetUserClaimValues(String s, Map<String, String> map, String s1) throws UserStoreException {

    }

    @Override
    protected void doDeleteUserClaimValue(String s, String s1, String s2) throws UserStoreException {

    }

    @Override
    protected void doDeleteUserClaimValues(String s, String[] strings, String s1) throws UserStoreException {

    }

    @Override
    protected void doUpdateUserListOfRole(String s, String[] strings, String[] strings1) throws UserStoreException {

    }

    @Override
    protected void doUpdateRoleListOfUser(String s, String[] strings, String[] strings1) throws UserStoreException {

    }

    @Override
    protected String[] doGetExternalRoleListOfUser(String s, String s1) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected String[] doGetSharedRoleListOfUser(String s, String s1, String s2) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected void doAddRole(String s, String[] strings, boolean b) throws UserStoreException {

    }

    @Override
    protected void doDeleteRole(String s) throws UserStoreException {

    }

    @Override
    protected void doUpdateRoleName(String s, String s1) throws UserStoreException {

    }

    @Override
    protected String[] doGetRoleNames(String s, int i) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected String[] doListUsers(String s, int i) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected String[] doGetDisplayNamesForInternalRole(String[] strings) throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean doCheckIsUserInRole(String s, String s1) throws UserStoreException {
        return false;
    }

    @Override
    protected String[] doGetSharedRoleNames(String s, String s1, int i) throws UserStoreException {
        return new String[0];
    }

    @Override
    protected String[] doGetUserListOfRole(String s, String s1) throws UserStoreException {
        return new String[0];
    }
}
