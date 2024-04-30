package org.wso2.dashboard.security.user.core;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.dashboard.security.user.core.file.FileBasedUserStoreManager;
import org.wso2.dashboard.security.user.core.ldap.ReadOnlyLDAPUserStoreManager;
import org.wso2.micro.integrator.security.MicroIntegratorSecurityUtils;
//import org.wso2.micro.integrator.security.SecurityConstants;
import org.wso2.micro.integrator.security.internal.DataHolder;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
//import org.wso2.micro.integrator.security.user.api.UserStoreManager;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.common.AbstractUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.UserStore;
import org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants;
import org.wso2.micro.integrator.security.user.core.ldap.LDAPConstants;
import org.wso2.micro.integrator.security.user.core.util.UserCoreUtil;
//import org.wso2.micro.integrator.security.user.core.ldap.ReadOnlyLDAPUserStoreManager;

import java.util.Hashtable;
import java.util.Map;

public class UserStoreManagerUtils {
    private static Log log = LogFactory.getLog(UserStoreManagerUtils.class);
    private static final String MULIPLE_ATTRIBUTE_ENABLE = "MultipleAttributeEnable";

    public static boolean validateUserNameAndCredential(String userName, String credential) {
        boolean isValid = true;
        if (userName == null || credential == null) {
            String message = String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getMessage(), "Authentication failure. Either Username or Password is null");
//            this.handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getCode(), message, userName, credential);
            log.error(message);
            isValid = false;
        }

        return isValid;
    }

    public static UserStoreManager getUserStoreManager() throws UserStoreException {
//        todo:may be we can have a seperate DataHolder for dashboard. so that we dont have to cast
        DataHolder dataHolder = DataHolder.getInstance();
        if (dataHolder.getUserStoreManager() == null) {
            initializeUserStore();
        }
        return (UserStoreManager) dataHolder.getUserStoreManager();
    }

    public static void initializeUserStore() throws UserStoreException {
        DataHolder dataHolder = DataHolder.getInstance();
        if (Boolean.parseBoolean(System.getProperty("is.user.store.file.based"))) {
            dataHolder.setUserStoreManager(FileBasedUserStoreManager.getUserStoreManager());
        } else {
            RealmConfiguration config = RealmConfigXMLProcessor.createRealmConfig();
            if (config == null) {
                throw new UserStoreException("Unable to create Realm Configuration");
            }
            dataHolder.setRealmConfig(config);

            UserStoreManager userStoreManager;
            String userStoreMgtClassStr = config.getUserStoreClass();
            switch (userStoreMgtClassStr) {
                case UserStoreConstants.DEFAULT_LDAP_USERSTORE_MANAGER:
                    userStoreManager = new ReadOnlyLDAPUserStoreManager(config, null, null);
                    break;
                case UserStoreConstants.DEFAULT_JDBC_USERSTORE_MANAGER:
                    userStoreManager = new JDBCUserStoreManager(config, new Hashtable<>(), null, null, null,
                            Constants.SUPER_TENANT_ID, false);
                    break;
                default:
                    userStoreManager = (UserStoreManager) MicroIntegratorSecurityUtils.
                            createObjectWithOptions(userStoreMgtClassStr, config);
                    break;
            }
//            todo: lets make this one class
            dataHolder.setUserStoreManager((org.wso2.micro.integrator.security.user.api.UserStoreManager) userStoreManager);
        }
    }

    public static String addDomainToName(String name, String domainName) {

        if (!name.contains(UserStoreConstants.DOMAIN_SEPARATOR) &&
                !UserStoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME.equalsIgnoreCase(domainName)) {
            // domain name is not already appended, and if exist in user-mgt.xml, append it..
            if (domainName != null) {
                // append domain name if exist
                domainName = domainName.toUpperCase() + UserStoreConstants.DOMAIN_SEPARATOR;
                name = domainName + name;
            }
        }
        return name;
    }

    public String[] getRoleListOfUser(String userName) throws UserStoreException {
        return DataHolder.getInstance().getUserStoreManager().getRoleListOfUser(userName);
    }

    protected String getMyDomainName(RealmConfiguration realmConfig) {
        return UserCoreUtil.getDomainName(realmConfig);
    }





    public static boolean isAdmin(String user) throws UserStoreException {
        String[] roles = getUserStoreManager().doGetRoleListOfUser(user);
        return false;
//        return containsAdminRole(roles);
    }

}
