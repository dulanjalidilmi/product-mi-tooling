package org.wso2.dashboard.security.user.core.jdbc;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.DatabaseUtil;
import org.wso2.dashboard.security.user.core.UserStoreManager;
import org.wso2.dashboard.security.user.core.UserStoreManagerUtils;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.common.AbstractUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.jdbc.JDBCRealmConstants;
import org.wso2.micro.integrator.security.user.core.jdbc.caseinsensitive.JDBCCaseInsensitiveConstants;
import org.wso2.micro.integrator.security.user.core.profile.ProfileConfigurationManager;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
//lets see if we can remove
//import org.wso2.micro.integrator.security.user.core.util.DatabaseUtil;
import org.wso2.micro.integrator.security.user.core.util.JDBCRealmUtil;

import javax.sql.DataSource;
import java.security.*;
import java.sql.*;
import java.sql.Timestamp;
import java.util.*;
import java.util.Date;

public class JDBCUserStoreManager extends AbstractUserStoreManager implements UserStoreManager {
    private static Log log = LogFactory.getLog(JDBCUserStoreManager.class);
    private static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    protected DataSource jdbcds = null;

    public JDBCUserStoreManager() {

    }

    public JDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
                                ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
                                Integer tenantId, boolean skipInitData) throws UserStoreException {
        this(realmConfig, tenantId);
        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.claimManager = claimManager;
        this.userRealm = realm;

        try {
            jdbcds = loadUserStoreSpacificDataSoruce();

            if (jdbcds == null) {
                jdbcds = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
            }
            if (jdbcds == null) {
                jdbcds = DatabaseUtil.getRealmDataSource(realmConfig);
                properties.put(UserCoreConstants.DATA_SOURCE, jdbcds);
            }

            if (log.isDebugEnabled()) {
                log.debug("The jdbcDataSource being used by JDBCUserStoreManager :: "
                        + jdbcds.hashCode());
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Loading JDBC datasource failed", e);
            }
        }

//        todo
        dataSource = (DataSource) properties.get(UserCoreConstants.DATA_SOURCE);
        if (dataSource == null) {
            dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        }
        if (dataSource == null) {
            throw new UserStoreException("User Management Data Source is null");
        }
        properties.put(UserCoreConstants.DATA_SOURCE, dataSource);

        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig
                .getUserStoreProperties()));
// todo
// todo results: this.persistdomain insert the domain name. so this is not needed.
//        if (!fileBasedUserStoreMode) {
//            this.persistDomain();
//        }

//        todo
//        doInitialSetup(fileBasedUserStoreMode);
//        doInitialSetup(false);
//        if (!skipInitData && realmConfig.isPrimary()) {
//            addInitialAdminData(Boolean.parseBoolean(realmConfig.getAddAdmin()),
//                    !isInitSetupDone());
//        }

        if (log.isDebugEnabled()) {
            log.debug("Ended " + System.currentTimeMillis());
        }
    }

    public JDBCUserStoreManager(RealmConfiguration realmConfig, int tenantId) throws UserStoreException {
        this.realmConfig = realmConfig;
        this.tenantId = tenantId;
        realmConfig.setUserStoreProperties(JDBCRealmUtil.getSQL(realmConfig
                .getUserStoreProperties()));

        // new properties after carbon core 4.0.7 release.
        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (log.isDebugEnabled()) {
            if (readGroupsEnabled) {
                log.debug("ReadGroups is enabled for " + getMyDomainName());
            } else {
                log.debug("ReadGroups is disabled for " + getMyDomainName());
            }
        }

        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED) != null) {
            writeGroupsEnabled = Boolean.parseBoolean(realmConfig
                    .getUserStoreProperty(UserCoreConstants.RealmConfig.WRITE_GROUPS_ENABLED));
        } else {
            if (!isReadOnly()) {
                writeGroupsEnabled = true;
            }
        }

        System.out.println("sdfsdfjsdf");

        if (log.isDebugEnabled()) {
            if (writeGroupsEnabled) {
                log.debug("WriteGroups is enabled for " + getMyDomainName());
            } else {
                log.debug("WriteGroups is disabled for " + getMyDomainName());
            }
        }
// todo we can remove this of possible
        // This property is now deprecated
        if (realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_INTERNAL_ROLES_ONLY) != null) {
            boolean internalRolesOnly = Boolean
                    .parseBoolean(realmConfig
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_INTERNAL_ROLES_ONLY));
            if (internalRolesOnly) {
                readGroupsEnabled = false;
                writeGroupsEnabled = false;
            } else {
                readGroupsEnabled = true;
                writeGroupsEnabled = true;
            }
        }


        if (writeGroupsEnabled) {
            readGroupsEnabled = true;
        }

//        System.out.println("sdfsdfsdf");

    }

    /**
     * @return
     * @throws UserStoreException
     */
    private DataSource loadUserStoreSpacificDataSoruce() throws UserStoreException {
        try {
            return DatabaseUtil.createUserStoreDataSource(realmConfig);
        } catch (Throwable e) {
            log.error(e.getMessage());
            e.printStackTrace();
//            log.error(e.getStackTrace());
        }
        return null;
    }





//    todo this is written because no classdef occurs

    public boolean doAuthenticate(String userName, String credential) throws UserStoreException {
        try {

            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws Exception {
                    if (!UserStoreManagerUtils.validateUserNameAndCredential(userName, credential)) {
                        return  false;
                    }
    //                todo
    //                int index = userName.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
                    int index = userName.indexOf("/");
                    boolean domainProvided = index > 0;

//                    return authenticate(userName, credential, domainProvided);
                    return doConnectAndAuthenticate(userName, credential);
                }
            });
        } catch (PrivilegedActionException e) {
            if (!(e.getException() instanceof UserStoreException)) {
    //            handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(),
    //                    String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(), e.getMessage()),
    //                    userName, credential);
            }
            throw (UserStoreException) e.getException();
        }
    }

    public String[] doGetRoleListOfUser(String username) throws UserStoreException {
        //    todo check filter
        String filter = "*";
        if (log.isDebugEnabled()) {
            log.debug("Getting roles of user: " + username + " with filter: " + filter);
        }

        String sqlStmt;
        String[] names;
        if (filter.equals("*") || StringUtils.isEmpty(filter)) {

            sqlStmt = getExternalRoleListSqlStatement(
                    realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_USER_ROLE),
                    realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.GET_USER_ROLE_CASE_INSENSITIVE));
            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                names = getStringValuesFromDatabase(sqlStmt, username, tenantId, tenantId, tenantId);
            } else {
                names = getStringValuesFromDatabase(sqlStmt, username);
            }
        } else {
            filter = filter.trim();
            filter = filter.replace("*", "%");
            filter = filter.replace("?", "_");
            sqlStmt = getExternalRoleListSqlStatement(
                    realmConfig.getUserStoreProperty(JDBCRealmConstants.GET_IS_USER_ROLE_EXIST), realmConfig
                            .getUserStoreProperty(
                                    JDBCCaseInsensitiveConstants.GET_IS_USER_ROLE_EXIST_CASE_INSENSITIVE));

            if (sqlStmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                names = getStringValuesFromDatabase(sqlStmt, username, tenantId, tenantId, tenantId, filter);
            } else {
                names = getStringValuesFromDatabase(sqlStmt, username, filter);
            }
        }
        List<String> roles = new ArrayList<String>();
        if (log.isDebugEnabled()) {
            if (names != null) {
                for (String name : names) {
                    log.debug("Found role: " + name);
                }
            } else {
                log.debug("No external role found for the user: " + username);
            }
        }

        Collections.addAll(roles, names);
        return roles.toArray(new String[roles.size()]);

//        return new String[0];
    }

    @Override
    public boolean isAdmin(String username) throws UserStoreException {
        return false;
    }

    public boolean doConnectAndAuthenticate(String userName, Object credential) throws UserStoreException {

//        if (!checkUserNameValid(userName)) {
//            if (log.isDebugEnabled()) {
//                log.debug("Username validation failed");
//            }
//            return false;
//        }
//
//        if (!checkUserPasswordValid(credential)) {
//            if (log.isDebugEnabled()) {
//                log.debug("Password validation failed");
//            }
//            return false;
//        }

//        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
//            log.error("Anonnymous user trying to login");
//            return false;
//        }

        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        String sqlstmt = null;
        String password = null;
        boolean isAuthed = false;

        try {
            dbConnection = getDBConnection();
            dbConnection.setAutoCommit(false);

            if (isCaseSensitiveUsername()) {
                sqlstmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.SELECT_USER);
            } else {
                sqlstmt = realmConfig.getUserStoreProperty(JDBCCaseInsensitiveConstants.SELECT_USER_CASE_INSENSITIVE);
            }

            if (log.isDebugEnabled()) {
                log.debug(sqlstmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlstmt);
            prepStmt.setString(1, userName);
            if (sqlstmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, tenantId);
            }

            rs = prepStmt.executeQuery();

            if (rs.next() == true) {
                String storedPassword = rs.getString(3);
                String saltValue = null;
                if ("true".equalsIgnoreCase(realmConfig
                        .getUserStoreProperty(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = rs.getString(4);
                }

                boolean requireChange = rs.getBoolean(5);
                Timestamp changedTime = rs.getTimestamp(6);

                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();

                if (requireChange == true && changedTime.before(date)) {
                    isAuthed = false;
                } else {
                    password = preparePassword(credential.toString(), saltValue);
                    if ((storedPassword != null) && (storedPassword.equals(password))) {
                        isAuthed = true;
                    }
                }
            }
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving user authentication info for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException("Authentication Failure", e);
        } finally {
//            todo
//            org.wso2.micro.integrator.security.user.core.util.DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }

        return isAuthed;
    }

    /**
     * @param sqlStmt
     * @param params
     * @return
     * @throws UserStoreException
     */
    private String[] getStringValuesFromDatabase(String sqlStmt, Object... params)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Executing Query: " + sqlStmt);
            for (int i = 0; i < params.length; i++) {
                Object param = params[i];
                log.debug("Input value: " + param);
            }
        }

        String[] values = new String[0];
        Connection dbConnection = null;
        PreparedStatement prepStmt = null;
        ResultSet rs = null;
        try {
            dbConnection = getDBConnection();
            values = DatabaseUtil.getStringValuesFromDatabase(dbConnection, sqlStmt, params);
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving string values.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
//            org.wso2.micro.integrator.security.user.core.util.DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }
        return values;
    }

    /**
     * Get the SQL statement for ExternalRoles.
     *
     * @param caseSensitiveUsernameQuery    query for getting role with case sensitive username.
     * @param nonCaseSensitiveUsernameQuery query for getting role with non-case sensitive username.
     * @return sql statement.
     * @throws UserStoreException
     */
    private String getExternalRoleListSqlStatement(String caseSensitiveUsernameQuery,
                                                   String nonCaseSensitiveUsernameQuery) throws UserStoreException {
        String sqlStmt;
        if (isCaseSensitiveUsername()) {
            sqlStmt = caseSensitiveUsernameQuery;
        } else {
            sqlStmt = nonCaseSensitiveUsernameQuery;
        }
        if (sqlStmt == null) {
            throw new UserStoreException("The sql statement for retrieving user roles is null");
        }
        return sqlStmt;
    }

    private String preparePassword(String password, String saltValue) throws UserStoreException {
        try {
            String digestInput = password;
            if (saltValue != null) {
                digestInput = password + saltValue;
            }
            String digsestFunction = realmConfig.getUserStoreProperties().get(
                    JDBCRealmConstants.DIGEST_FUNCTION);
            if (digsestFunction != null) {

                if (digsestFunction
                        .equals(UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                    return password;
                }

                MessageDigest dgst = MessageDigest.getInstance(digsestFunction);
                byte[] byteValue = dgst.digest(digestInput.getBytes());
                password = Base64.encode(byteValue);
            }
            return password;
        } catch (NoSuchAlgorithmException e) {
            String msg = "Error occurred while preparing password.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        }
    }

    private boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    protected Connection getDBConnection() throws SQLException, UserStoreException {
        Connection dbConnection = getJDBCDataSource().getConnection();
        dbConnection.setAutoCommit(false);
        if (dbConnection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED) {
            dbConnection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
        }
        return dbConnection;
    }

    private DataSource getJDBCDataSource() throws UserStoreException {
        if (jdbcds == null) {
            jdbcds = loadUserStoreSpacificDataSoruce();
        }
        return jdbcds;
    }














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

//    @Override
//    protected boolean doAuthenticate(String s, Object o) throws DashboardUserStoreException {
//        return false;
//    }

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

//    @Override
//    public boolean doAuthenticate(String username, String password) {
//        return false;
//    }
}

