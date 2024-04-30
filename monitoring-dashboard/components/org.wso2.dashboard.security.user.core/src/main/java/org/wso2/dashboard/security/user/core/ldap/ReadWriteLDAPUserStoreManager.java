package org.wso2.dashboard.security.user.core.ldap;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.logging.log4j.Logger;
import org.wso2.dashboard.security.user.core.User;
import org.wso2.dashboard.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.UnsupportedSecretTypeException;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.common.AbstractUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.IterativeUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.UserStore;
import org.wso2.micro.integrator.security.user.core.constants.UserCoreErrorConstants;
import org.wso2.micro.integrator.security.user.core.internal.UMListenerServiceComponent;
import org.wso2.micro.integrator.security.user.core.listener.SecretHandleableListener;
import org.wso2.micro.integrator.security.user.core.listener.UserOperationEventListener;
import org.wso2.micro.integrator.security.user.core.listener.UserStoreManagerListener;
import org.wso2.micro.integrator.security.user.core.profile.ProfileConfigurationManager;
import org.wso2.micro.integrator.security.user.core.util.UserCoreUtil;
import org.wso2.micro.integrator.security.util.Secret;

import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.ArrayList;
import java.util.List;

//todo add random and all from MI

public class ReadWriteLDAPUserStoreManager extends ReadOnlyLDAPUserStoreManager implements UserStoreManager {
    private static Log log = LogFactory.getLog(ReadWriteLDAPUserStoreManager.class);
    public ReadWriteLDAPUserStoreManager() {

    }

    /**
     * This constructor is not used. So not applying the changes done to above constructor.
     *
     * @param realmConfig
     * @param claimManager
     * @param profileManager
     * @throws UserStoreException
     */
    public ReadWriteLDAPUserStoreManager(RealmConfiguration realmConfig, ClaimManager claimManager,
                                         ProfileConfigurationManager profileManager) throws UserStoreException {
        super(realmConfig, claimManager, profileManager);
    }

    @Override
//    public final boolean authenticate(final String userName, final Object credential) throws DashboardUserStoreException {
    public boolean doAuthenticate(String userName, String credential) throws UserStoreException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws Exception {
//                    if (!validateUserNameAndCredential(userName, credential)) {
//                        return  false;
//                    }
//                    int index = userName.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
                    int index = userName.indexOf("/");
                    boolean domainProvided = index > 0;
                    return authenticate(userName, credential, domainProvided);
                }
            });
        } catch (PrivilegedActionException e) {
            if (!(e.getException() instanceof UserStoreException)) {
//                handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(),
//                        String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(), e.getMessage()),
//                        userName, credential);
                System.out.println("Error while authenticating user: " + e.getMessage());
            }
            throw (UserStoreException) e.getException();
        }
    }

    protected boolean authenticate(final String userName, final Object credential, final boolean domainProvided)
            throws UserStoreException {

        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws Exception {
                    return authenticateInternalIteration(userName, credential, domainProvided);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }

    }

    private boolean authenticateInternalIteration(String userName, Object credential, boolean domainProvided)
            throws UserStoreException {

        List<String> userStorePreferenceOrder = new ArrayList<>();
        // Check whether user store chain needs to be generated or not.
//        if (isUserStoreChainNeeded(userStorePreferenceOrder)) {
//            if (log.isDebugEnabled()) {
//                log.debug("User store chain generation is needed hence generating the user store chain using the user" +
//                        " store preference order: " + userStorePreferenceOrder);
//            }
//            return generateUserStoreChain(userName, credential, domainProvided, userStorePreferenceOrder);
//        } else {
            // Authenticate the user.
            return authenticateInternal(userName, credential, domainProvided);
//        }
    }

    /**
     * @param userName
     * @param credential
     * @param domainProvided
     * @return
     * @throws UserStoreException
     */
    private boolean authenticateInternal(String userName, Object credential, boolean domainProvided)
            throws UserStoreException {
//        boolean authenticated = false;

//        AbstractUserStoreManager abstractUserStoreManager = this;
        ReadWriteLDAPUserStoreManager readWriteLDAPUserStoreManager = this;
//        if (this instanceof IterativeUserStoreManager) {
//            abstractUserStoreManager = ((IterativeUserStoreManager) this).getAbstractUserStoreManager();
//        }
//
        boolean authenticated = false;
//
        UserStore userStore = readWriteLDAPUserStoreManager.getUserStore(userName);
//        UserStore userStore = abstractUserStoreManager.getUserStore(userName);
//        if (userStore.isRecurssive() && userStore.getUserStoreManager() instanceof AbstractUserStoreManager) {
//            return ((AbstractUserStoreManager) userStore.getUserStoreManager()).authenticate(userStore.getDomainFreeName(),
//                    credential, domainProvided);
//        }
//
//        Secret credentialObj;
//        try {
//            credentialObj = Secret.getSecret(credential);
//        } catch (UnsupportedSecretTypeException e) {
//            handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getCode(),
//                    UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.getMessage(), userName, credential);
//            throw new DashboardUserStoreException(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_UNSUPPORTED_CREDENTIAL_TYPE.toString(), e);
//        }
//
//        // #################### Domain Name Free Zone Starts Here ################################
//
//        // #################### <Listeners> #####################################################
//        try {
//            for (UserStoreManagerListener listener : UMListenerServiceComponent.getUserStoreManagerListeners()) {
//                Object credentialArgument;
//                if (listener instanceof SecretHandleableListener) {
//                    credentialArgument = credentialObj;
//                } else {
//                    credentialArgument = credential;
//                }
//
//                if (!listener.authenticate(userName, credentialArgument, abstractUserStoreManager)) {
//                    handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(),
//                            UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(), userName,
//                            credentialArgument);
//                    return true;
//                }
//            }
//
//            try {
//                for (UserOperationEventListener listener : UMListenerServiceComponent
//                        .getUserOperationEventListeners()) {
//                    Object credentialArgument;
//                    if (listener instanceof SecretHandleableListener) {
//                        credentialArgument = credentialObj;
//                    } else {
//                        credentialArgument = credential;
//                    }
//
//                    if (!listener.doPreAuthenticate(userName, credentialArgument, abstractUserStoreManager)) {
//                        handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getCode(),
//                                String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getMessage(),
//                                        UserCoreErrorConstants.PRE_LISTENER_TASKS_FAILED_MESSAGE), userName,
//                                credentialArgument);
//                        return false;
//                    }
//                }
//            } catch (DashboardUserStoreException ex) {
//                handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getCode(),
//                        String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_PRE_AUTHENTICATION.getMessage(),
//                                ex.getMessage()), userName, credential);
//                throw ex;
//            }
//            // #################### </Listeners> #####################################################
//
//            int tenantId = abstractUserStoreManager.getTenantId();
//
//            // We are here due to two reason. Either there is no secondary UserStoreManager or no
//            // domain name provided with user name.
//
            try {
                // Let's authenticate with the primary UserStoreManager.
                authenticated = readWriteLDAPUserStoreManager.doAuthenticate(userName, credential);
            } catch (Exception e) {
//                handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(),
//                        String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(), e.getMessage()),
//                        userName, credential);
                log.error("Error occurred while authenticating user: " + userName, e);
                // We can ignore and proceed. Ignore the results from this user store.

                if (log.isDebugEnabled()) {
                    log.debug("Error occurred while authenticating user: " + userName, e);
                } else {
                    log.error(e);
                }
                authenticated = false;
            }
//
//        } finally {
//            credentialObj.clear();
//        }
//
//        if (authenticated) {
//            // Set domain in thread local variable for subsequent operations
//            UserCoreUtil.setDomainInThreadLocal(UserCoreUtil.getDomainName(abstractUserStoreManager.realmConfig));
//        }
//
//        // If authentication fails in the previous step and if the user has not specified a
//        // domain- then we need to execute chained UserStoreManagers recursively.
//        if (!authenticated && !domainProvided) {
//            AbstractUserStoreManager userStoreManager;
//            if (this instanceof IterativeUserStoreManager) {
//                IterativeUserStoreManager iterativeUserStoreManager = (IterativeUserStoreManager) this;
//                userStoreManager = iterativeUserStoreManager.nextUserStoreManager();
//            } else {
//                userStoreManager = (AbstractUserStoreManager) abstractUserStoreManager.getSecondaryUserStoreManager();
//            }
//            if (userStoreManager != null) {
//                authenticated = userStoreManager.authenticate(userName, credential, domainProvided);
//            }
//        }
//
//        if (!authenticated) {
//            handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getCode(),
//                    String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_AUTHENTICATION.getMessage(),
//                            "Authentication failed"), userName, credential);
//        }
//
//        try {
//            // You cannot change authentication decision in post handler to TRUE
//            for (UserOperationEventListener listener : UMListenerServiceComponent.getUserOperationEventListeners()) {
//                if (!listener.doPostAuthenticate(userName, authenticated, abstractUserStoreManager)) {
//                    handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_POST_AUTHENTICATION.getCode(),
//                            String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_POST_AUTHENTICATION.getMessage(),
//                                    UserCoreErrorConstants.POST_LISTENER_TASKS_FAILED_MESSAGE), userName, credential);
//                    return false;
//                }
//            }
//        } catch (DashboardUserStoreException ex) {
//            handleOnAuthenticateFailure(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_POST_AUTHENTICATION.getCode(),
//                    String.format(UserCoreErrorConstants.ErrorMessages.ERROR_CODE_ERROR_WHILE_POST_AUTHENTICATION.getMessage(),
//                            ex.getMessage()), userName, credential);
//            throw ex;
//        }
//
//        if (log.isDebugEnabled()) {
//            if (!authenticated) {
//                log.debug("Authentication failure. Wrong username or password is provided.");
//            }
//        }

        return authenticated;
    }


    private org.wso2.micro.integrator.security.user.core.common.UserStore getUserStore(final String user) throws UserStoreException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<org.wso2.micro.integrator.security.user.core.common.UserStore>() {
                @Override
                public org.wso2.micro.integrator.security.user.core.common.UserStore run() throws Exception {
                    return getUserStoreInternal(user);
                }
            });
        } catch (PrivilegedActionException e) {
            throw (UserStoreException) e.getException();
        }
    }

    /**
     * @return
     * @throws UserStoreException
     */
    private org.wso2.micro.integrator.security.user.core.common.UserStore getUserStoreInternal(String user) throws UserStoreException {

        int index;
//        index = user.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
        index = user.indexOf("/");
        org.wso2.micro.integrator.security.user.core.common.UserStore userStore = new org.wso2.micro.integrator.security.user.core.common.UserStore();
        String domainFreeName = null;

        // Check whether we have a secondary UserStoreManager setup.
        if (index > 0) {
            // Using the short-circuit. User name comes with the domain name.
            String domain = user.substring(0, index);
            org.wso2.micro.integrator.security.user.core.UserStoreManager secManager = getSecondaryUserStoreManager(domain);
            domainFreeName = user.substring(index + 1);

            if (secManager != null) {
                userStore.setUserStoreManager(secManager);
                userStore.setDomainAwareName(user);
                userStore.setDomainFreeName(domainFreeName);
                userStore.setDomainName(domain);
                userStore.setRecurssive(true);
                return userStore;
            } else {
                if (!domain.equalsIgnoreCase(getMyDomainName())) {
//                    if ((UserCoreConstants.INTERNAL_DOMAIN.equalsIgnoreCase(domain)
//                            || APPLICATION_DOMAIN.equalsIgnoreCase(domain) || WORKFLOW_DOMAIN.equalsIgnoreCase(domain))) {
//                        userStore.setHybridRole(true);
//                    } else if (UserCoreConstants.SYSTEM_DOMAIN_NAME.equalsIgnoreCase(domain)) {
//                        userStore.setSystemStore(true);
//                    } else {
//                        throw new DashboardUserStoreException("Invalid Domain Name");
//                    }
                }

                userStore.setDomainAwareName(user);
                userStore.setDomainFreeName(domainFreeName);
                userStore.setDomainName(domain);
                userStore.setRecurssive(false);
                return userStore;
            }
        }

        String domain = getMyDomainName();
        userStore.setUserStoreManager(this);
        if (index > 0) {
            userStore.setDomainAwareName(user);
            userStore.setDomainFreeName(domainFreeName);
        } else {
//            userStore.setDomainAwareName(domain + UserCoreConstants.DOMAIN_SEPARATOR + user);
            userStore.setDomainAwareName(domain + "/" + user);
            userStore.setDomainFreeName(user);
        }
        userStore.setRecurssive(false);
        userStore.setDomainName(domain);

        return userStore;
    }

    @Override
    public String[] doGetRoleListOfUser(String username) throws UserStoreException {
        return new String[0];
    }

//    todo: implement isAdmin
    @Override
    public boolean isAdmin(String username) throws UserStoreException {
        return false;
    }
}
