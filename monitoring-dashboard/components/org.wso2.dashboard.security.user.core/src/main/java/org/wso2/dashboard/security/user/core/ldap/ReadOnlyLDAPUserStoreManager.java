package org.wso2.dashboard.security.user.core.ldap;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.dashboard.security.user.core.AbstractUserStoreManager2;
import org.wso2.dashboard.security.user.core.DatabaseUtil;
import org.wso2.dashboard.security.user.core.UserStoreManager;
import org.wso2.micro.integrator.security.UnsupportedSecretTypeException;
import org.wso2.micro.integrator.security.user.api.Properties;
import org.wso2.micro.integrator.security.user.api.Property;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.core.UserCoreConstants;
import org.wso2.micro.integrator.security.user.core.UserStoreException;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.common.AbstractUserStoreManager;
import org.wso2.micro.integrator.security.user.core.common.RoleContext;
import org.wso2.micro.integrator.security.user.core.hybrid.HybridRoleManager;
import org.wso2.micro.integrator.security.user.core.ldap.LDAPConstants;
import org.wso2.micro.integrator.security.user.core.profile.ProfileConfigurationManager;
import org.wso2.micro.integrator.security.user.core.tenant.Tenant;
import org.wso2.micro.integrator.security.user.core.util.JNDIUtil;
import org.wso2.micro.integrator.security.user.core.util.UserCoreUtil;
import org.wso2.micro.integrator.security.util.Secret;

import javax.cache.CacheBuilder;
import javax.cache.CacheManager;
import javax.naming.*;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ReadOnlyLDAPUserStoreManager extends AbstractUserStoreManager implements UserStoreManager {
    public static final String MEMBER_UID = "memberUid";
    private static final String OBJECT_GUID = "objectGUID";
    protected static final String MEMBERSHIP_ATTRIBUTE_RANGE = "MembershipAttributeRange";
    protected static final String MEMBERSHIP_ATTRIBUTE_RANGE_DISPLAY_NAME = "Membership Attribute Range";
    private static final String USER_CACHE_NAME_PREFIX = UserCoreConstants.CachingConstants.LOCAL_CACHE_PREFIX + "UserCache-";
    private static final String USER_CACHE_MANAGER = "UserCacheManager";
    private static Log log = LogFactory.getLog(org.wso2.micro.integrator.security.user.core.ldap.ReadOnlyLDAPUserStoreManager.class);
    protected static final int MAX_USER_CACHE = 200;

    private static final String MULTI_ATTRIBUTE_SEPARATOR_DESCRIPTION = "This is the separator for multiple claim values";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private static final ArrayList<Property> RO_LDAP_UM_ADVANCED_PROPERTIES = new ArrayList<Property>();
    private static final String PROPERTY_REFERRAL_IGNORE ="ignore";
    private static final String LDAPConnectionTimeout = "LDAPConnectionTimeout";
    private static final String LDAPConnectionTimeoutDescription = "LDAP Connection Timeout";
    private static final String readTimeout = "ReadTimeout";
    private static final String readTimeoutDescription = "Configure this to define the read timeout for LDAP operations";
    private static final String RETRY_ATTEMPTS = "RetryAttempts";
    private static final String LDAPBinaryAttributesDescription = "Configure this to define the LDAP binary attributes " +
            "seperated by a space. Ex:mpegVideo mySpecialKey";
    protected static final String USER_CACHE_EXPIRY_TIME_ATTRIBUTE_NAME = "User Cache Expiry milliseconds";
    protected static final String USER_DN_CACHE_ENABLED_ATTRIBUTE_NAME = "Enable User DN Cache";
    protected static final String USER_CACHE_EXPIRY_TIME_ATTRIBUTE_DESCRIPTION =
            "Configure the user cache expiry in milliseconds. "
                    + "Values  {0: expire immediately, -1: never expire, '': i.e. empty, system default}.";
    protected static final String USER_DN_CACHE_ENABLED_ATTRIBUTE_DESCRIPTION = "Enables the user cache. Default true,"
            + " Unless set to false. Empty value is interpreted as true.";
    //Authenticating to LDAP via Anonymous Bind
    private static final String USE_ANONYMOUS_BIND = "AnonymousBind";
    protected static final int MEMBERSHIP_ATTRIBUTE_RANGE_VALUE = 0;

    private String cacheExpiryTimeAttribute = ""; //Default: expire with default system wide cache expiry
    private long userDnCacheExpiryTime = 0; //Default: No cache
    private CacheBuilder userDnCacheBuilder = null; //Use cache manager if not null to get cache
    private String userDnCacheName;
    private boolean userDnCacheEnabled = true;
    protected CacheManager cacheManager;
    protected String tenantDomain;

    /**
     * The use of this Map is Deprecated. Please use userDnCache.
     * Retained so that any extended class will function as it used to be.
     */
    @Deprecated
    Map<String, Object> userCache = new ConcurrentHashMap<>(MAX_USER_CACHE);
    protected LDAPConnectionContext connectionSource = null;
    protected String userSearchBase = null;
    protected String groupSearchBase = null;

    /*
     * following is by default true since embedded-ldap allows it. If connected
     * to an external ldap
     * where empty roles not allowed, then following property should be set
     * accordingly in
     * user-mgt.xml
     */
    protected boolean emptyRolesAllowed = false;

    private boolean fileBasedUserStoreMode = false;

    static {
//        setAdvancedProperties();
    }

    public ReadOnlyLDAPUserStoreManager() {

    }

    /**
     * This operates in the pure read-only mode without a connection to a
     * database. No handling of
     * Internal roles.
     */
    public ReadOnlyLDAPUserStoreManager(RealmConfiguration realmConfig, ClaimManager claimManager,
                                        ProfileConfigurationManager profileManager)
            throws UserStoreException {

        if (log.isDebugEnabled()) {
            log.debug("Started " + System.currentTimeMillis());
        }
        this.realmConfig = realmConfig;
        this.claimManager = claimManager;

        // check if required configurations are in the user-mgt.xml
        checkRequiredUserStoreConfigurations();

        this.connectionSource = new LDAPConnectionContext(realmConfig);

        try {
            this.dataSource = DatabaseUtil.getRealmDataSource(realmConfig);
        } catch (Exception ex) {
            // datasource is not configured
            if (log.isDebugEnabled()) {
                log.debug("Datasource is not configured for LDAP user store");
            }
        }
        hybridRoleManager =
                new HybridRoleManager(dataSource, tenantId, realmConfig, userRealm);
    }

    /**
     * @throws UserStoreException
     */
    protected void checkRequiredUserStoreConfigurations() throws UserStoreException {

        log.debug("Checking LDAP configurations ");

        String connectionURL = realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_URL);
        String DNSURL = realmConfig.getUserStoreProperty(LDAPConstants.DNS_URL);
        String AnonymousBind = realmConfig.getUserStoreProperty(USE_ANONYMOUS_BIND);

        if ((connectionURL == null || connectionURL.trim().length() == 0) &&
                ((DNSURL == null || DNSURL.trim().length() == 0))) {
            throw new UserStoreException(
                    "Required ConnectionURL property is not set at the LDAP configurations");
        }
        if (!Boolean.parseBoolean(AnonymousBind)) {
            String connectionName = realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_NAME);
            if (StringUtils.isEmpty(connectionName)) {
                throw new UserStoreException(
                        "Required ConnectionNme property is not set at the LDAP configurations");
            }
            String connectionPassword =
                    realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_PASSWORD);
            if (StringUtils.isEmpty(connectionPassword)) {
                throw new UserStoreException(
                        "Required ConnectionPassword property is not set at the LDAP configurations");
            }
        }
        userSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        if (userSearchBase == null || userSearchBase.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserSearchBase property is not set at the LDAP configurations");
        }
        String usernameListFilter =
                realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_LIST_FILTER);
        if (usernameListFilter == null || usernameListFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameListFilter property is not set at the LDAP configurations");
        }

        String usernameSearchFilter =
                realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        if (usernameSearchFilter == null || usernameSearchFilter.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameSearchFilter property is not set at the LDAP configurations");
        }

        String usernameAttribute =
                realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        if (usernameAttribute == null || usernameAttribute.trim().length() == 0) {
            throw new UserStoreException(
                    "Required UserNameAttribute property is not set at the LDAP configurations");
        }

        writeGroupsEnabled = false;

        // Groups properties
        if (realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED) != null) {
            readGroupsEnabled = Boolean.parseBoolean(realmConfig.
                    getUserStoreProperty(UserCoreConstants.RealmConfig.READ_GROUPS_ENABLED));
        }

        if (log.isDebugEnabled()) {
            if (readGroupsEnabled) {
                log.debug("ReadGroups is enabled for " + getMyDomainName());
            } else {
                log.debug("ReadGroups is disabled for " + getMyDomainName());
            }
        }

        if (readGroupsEnabled) {
            groupSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_SEARCH_BASE);
            if (groupSearchBase == null || groupSearchBase.trim().length() == 0) {
                throw new UserStoreException(
                        "Required GroupSearchBase property is not set at the LDAP configurations");
            }
            String groupNameListFilter =
                    realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_LIST_FILTER);
            if (groupNameListFilter == null || groupNameListFilter.trim().length() == 0) {
                throw new UserStoreException(
                        "Required GroupNameListFilter property is not set at the LDAP configurations");
            }

            String groupNameSearchFilter =
                    realmConfig.getUserStoreProperty(LDAPConstants.ROLE_NAME_FILTER);
            if (groupNameSearchFilter == null || groupNameSearchFilter.trim().length() == 0) {
                throw new UserStoreException(
                        "Required GroupNameSearchFilter property is not set at the LDAP configurations");
            }

            String groupNameAttribute =
                    realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_ATTRIBUTE);
            if (groupNameAttribute == null || groupNameAttribute.trim().length() == 0) {
                throw new UserStoreException(
                        "Required GroupNameAttribute property is not set at the LDAP configurations");
            }
            String memebershipAttribute =
                    realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
            if (memebershipAttribute == null || memebershipAttribute.trim().length() == 0) {
                throw new UserStoreException(
                        "Required MembershipAttribute property is not set at the LDAP configurations");
            }
        }

        // User DN cache properties
        cacheExpiryTimeAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_CACHE_EXPIRY_MILLISECONDS);
        String userDnCacheEnabledAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_DN_CACHE_ENABLED);
        if (StringUtils.isNotEmpty(userDnCacheEnabledAttribute)) {
            userDnCacheEnabled = Boolean.parseBoolean(userDnCacheEnabledAttribute);
        }
    }

    @Override
    protected boolean doAuthenticate(String userName, Object credential) throws UserStoreException {
        boolean debug = log.isDebugEnabled();


        String failedUserDN = null;

        if (userName == null || credential == null) {
            return false;
        }

        String leadingOrTrailingSpaceAllowedInUserName = realmConfig.getUserStoreProperty(UserCoreConstants
                .RealmConfig.LEADING_OR_TRAILING_SPACE_ALLOWED_IN_USERNAME);
        if (StringUtils.isNotEmpty(leadingOrTrailingSpaceAllowedInUserName)) {
            boolean isSpaceAllowedInUserName = Boolean.parseBoolean(leadingOrTrailingSpaceAllowedInUserName);
            if (log.isDebugEnabled()) {
                log.debug("'LeadingOrTrailingSpaceAllowedInUserName' property is set to : " +
                        isSpaceAllowedInUserName);
            }
            if (!isSpaceAllowedInUserName) {
                if (log.isDebugEnabled()) {
                    log.debug("Leading or trailing spaces are not allowed in username. Hence validating the username" +
                            " against the regex for the user : " + userName);
                }
                // Need to validate the username against the regex.
                if (!checkUserNameValid(userName)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Username validation failed for the user : " + userName);
                    }
                    return false;
                }
            }
        } else {
            // Keeping old behavior for backward-compatibility.
            userName = userName.trim();
        }

//        Secret credentialObj;
//        try {
//            credentialObj = Secret.getSecret(credential);
//        } catch (UnsupportedSecretTypeException e) {
//            throw new DashboardUserStoreException("Unsupported credential type", e);
//        }
//
//        if (userName.equals("") || credentialObj.isEmpty()) {
//            return false;
//        }
        Object credentialObj = credential;

        if (debug) {
            log.debug("Authenticating user " + userName);
        }

        try {
            boolean bValue = false;
            // check cached user DN first.
            String name = null;
//            LdapName ldn = getFromUserCache(userName);

//            if (ldn != null) {
//                name = ldn.toString();
//                try {
//                    if (debug) {
//                        log.debug("Cache hit. Using DN " + name);
//                    }
//                    bValue = this.bindAsUser(userName, name, credentialObj);
//                } catch (NamingException e) {
//                    // do nothing if bind fails since we check for other DN
//                    // patterns as well.
//                    if (log.isDebugEnabled()) {
//                        log.debug("Checking authentication with UserDN " + name + "failed " + e.getMessage(), e);
//                    }
//                }
//
//                if (bValue) {
//                    return bValue;
//                }
//                // we need not check binding for this name again, so store this and check
//                failedUserDN = name;
//
//            }
            // read DN patterns from user-mgt.xml
            String patterns = realmConfig.getUserStoreProperty(LDAPConstants.USER_DN_PATTERN);

            if (patterns != null && !patterns.isEmpty()) {

//                if (debug) {
//                    log.debug("Using UserDNPatterns " + patterns);
//                }
//
//                // if the property is present, split it using # to see if there are
//                // multiple patterns specified.
//                String[] userDNPatternList = patterns.split("#");
//                if (userDNPatternList.length > 0) {
//                    for (String userDNPattern : userDNPatternList) {
//                        name = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));
//                        // check if the same name is found and checked from cache
//                        if (failedUserDN != null && failedUserDN.equalsIgnoreCase(name)) {
//                            continue;
//                        }
//
//                        if (debug) {
//                            log.debug("Authenticating with " + name);
//                        }
//                        try {
//                            if (name != null) {
//                                bValue = this.bindAsUser(userName, name, credentialObj);
//                                if (bValue) {
//                                    LdapName ldapName = new LdapName(name);
//                                    putToUserCache(userName, ldapName);
//                                    break;
//                                }
//                            }
//                        } catch (NamingException e) {
//                            // do nothing if bind fails since we check for other DN
//                            // patterns as well.
//                            if (log.isDebugEnabled()) {
//                                log.debug("Checking authentication with UserDN " + userDNPattern +
//                                        "failed " + e.getMessage(), e);
//                            }
//                        }
//                    }
//                }
            } else {
                name = getNameInSpaceForUsernameFromLDAP(userName);
                try {
                    if (name != null) {
                        // if it is the same user DN found in the cache no need of futher authentication required.
                        if (failedUserDN == null || !failedUserDN.equalsIgnoreCase(name)) {
                            if (log.isDebugEnabled()) {
                                log.debug("Authenticating with " + name);
                            }
                            bValue = this.bindAsUser(userName, name, credentialObj);
                            if (bValue) {
                                LdapName ldapName = new LdapName(name);
//                                putToUserCache(userName, ldapName);
                            }
                        }
                    }
                } catch (NamingException e) {
                    String errorMessage = "Cannot bind user : " + userName;
                    if (log.isDebugEnabled()) {
                        log.debug(errorMessage, e);
                    }
                    throw new UserStoreException(errorMessage, e);
                }
            }

            return bValue;
        } finally {
//            credentialObj.clear();
        }
    }

    /**
     * This is to search user and retrieve ldap name directly from ldap
     * @param userName
     * @return
     * @throws UserStoreException
     */
    protected String getNameInSpaceForUsernameFromLDAP(String userName) throws UserStoreException {

        String searchBase = null;
        String userSearchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
        userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
        String userDNPattern = realmConfig.getUserStoreProperty(LDAPConstants.USER_DN_PATTERN);
        if (userDNPattern != null && userDNPattern.trim().length() > 0) {
            String[] patterns = userDNPattern.split("#");
            for (String pattern : patterns) {
                searchBase = MessageFormat.format(pattern, escapeSpecialCharactersForDN(userName));
                String userDN = getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
                // check in another DN pattern
                if (userDN != null) {
                    return userDN;
                }
            }
        }

        searchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        return getNameInSpaceForUserName(userName, searchBase, userSearchFilter);
    }

    /**
     * Escaping ldap search filter special characters in a string
     *
     * @param dnPartial String to replace special characters of
     * @return
     */
    private String escapeSpecialCharactersForFilter(String dnPartial) {
        boolean replaceEscapeCharacters = true;
        dnPartial.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }
        //TODO: implement character escaping for *

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\5c");
                        break;
                    case '*':
                        sb.append("\\2a");
                        break;
                    case '(':
                        sb.append("\\28");
                        break;
                    case ')':
                        sb.append("\\29");
                        break;
                    case '\u0000':
                        sb.append("\\00");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    /**
     * Escaping ldap DN special characters in a String value
     *
     * @param text String to replace special characters of
     * @return
     */
    private String escapeSpecialCharactersForDN(String text) {
        boolean replaceEscapeCharacters = true;
        text.replace("\\*", "*");

        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean
                    .parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: "
                        + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            if ((text.length() > 0) && ((text.charAt(0) == ' ') || (text.charAt(0) == '#'))) {
                sb.append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < text.length(); i++) {
                char currentChar = text.charAt(i);
                switch (currentChar) {
                    case '\\':
                        sb.append("\\\\");
                        break;
                    case ',':
                        sb.append("\\,");
                        break;
                    case '+':
                        sb.append("\\+");
                        break;
                    case '"':
                        sb.append("\\\"");
                        break;
                    case '<':
                        sb.append("\\<");
                        break;
                    case '>':
                        sb.append("\\>");
                        break;
                    case ';':
                        sb.append("\\;");
                        break;
                    case '*':
                        sb.append("\\2a");
                        break;
                    default:
                        sb.append(currentChar);
                }
            }
            if ((text.length() > 1) && (text.charAt(text.length() - 1) == ' ')) {
                sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
            }
            if (log.isDebugEnabled()) {
                log.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }
    }

    /**
     * @param userName
     * @param searchBase
     * @param searchFilter
     * @return
     * @throws UserStoreException
     */
    protected String getNameInSpaceForUserName(String userName, String searchBase, String searchFilter) throws UserStoreException {
        boolean debug = log.isDebugEnabled();

        if (userName == null) {
            throw new UserStoreException("userName value is null.");
        }
//        Object cachedDn = getFromUserCache(userName);
//        if ( cachedDn != null) {
//            return cachedDn.toString();
//        }

        String userDN = null;

        DirContext dirContext = this.connectionSource.getContext();
        NamingEnumeration<SearchResult> answer = null;
        try {
            SearchControls searchCtls = new SearchControls();
            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            if (log.isDebugEnabled()) {
                try {
                    log.debug("Searching for user with SearchFilter: " + searchFilter + " in SearchBase: " + dirContext.getNameInNamespace());
                } catch (NamingException e) {
                    log.debug("Error while getting DN of search base", e);
                }
            }
            SearchResult userObj = null;
            String[] searchBases = searchBase.split("#");
            for (String base : searchBases) {
                answer = dirContext.search(escapeDNForSearch(base), searchFilter, searchCtls);
                if (answer.hasMore()) {
                    userObj = (SearchResult) answer.next();
                    if (userObj != null) {
                        //no need to decode since , if decoded the whole string, can't be encoded again
                        //eg CN=Hello\,Ok=test\,test, OU=Industry
                        userDN = userObj.getNameInNamespace();
                        break;
                    }
                }
            }
//            if (userDN != null) {
//                LdapName ldn = new LdapName(userDN);
//                putToUserCache(userName, ldn);
//            }
            if (debug) {
                log.debug("Name in space for " + userName + " is " + userDN);
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
            JNDIUtil.closeContext(dirContext);
        }
        return userDN;
    }


    /**
     * @param userName
     * @param dn
     * @param credentials
     * @return
     * @throws NamingException
     * @throws UserStoreException
     */
    private boolean bindAsUser(String userName, String dn, Object credentials) throws NamingException,
            UserStoreException {
        boolean isAuthed = false;
        boolean debug = log.isDebugEnabled();

        /*
         * Hashtable<String, String> env = new Hashtable<String, String>();
         * env.put(Context.INITIAL_CONTEXT_FACTORY, LDAPConstants.DRIVER_NAME);
         * env.put(Context.SECURITY_PRINCIPAL, dn);
         * env.put(Context.SECURITY_CREDENTIALS, credentials);
         * env.put("com.sun.jndi.ldap.connect.pool", "true");
         */
        /**
         * In carbon JNDI context we need to by pass specific tenant context and
         * we need the base
         * context for LDAP operations.
         */
        // env.put(CarbonConstants.REQUEST_BASE_CONTEXT, "true");

        /*
         * String rawConnectionURL =
         * realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_URL);
         * String portInfo = rawConnectionURL.split(":")[2];
         *
         * String connectionURL = null;
         * String port = null;
         * // if the port contains a template string that refers to carbon.xml
         * if ((portInfo.contains("${")) && (portInfo.contains("}"))) {
         * port =
         * Integer.toString(CarbonUtils.getPortFromServerConfig(portInfo));
         * connectionURL = rawConnectionURL.replace(portInfo, port);
         * }
         * if (port == null) { // if not enabled, read LDAP url from
         * user.mgt.xml
         * connectionURL =
         * realmConfig.getUserStoreProperty(LDAPConstants.CONNECTION_URL);
         * }
         */
        /*
         * env.put(Context.PROVIDER_URL, connectionURL);
         * env.put(Context.SECURITY_AUTHENTICATION, "simple");
         */

        LdapContext cxt = null;
        try {
            // cxt = new InitialLdapContext(env, null);
            cxt = this.connectionSource.getContextWithCredentials(dn, credentials);
            isAuthed = true;
        } catch (AuthenticationException e) {
            /*
             * StringBuilder stringBuilder = new
             * StringBuilder("Authentication failed for user ");
             * stringBuilder.append(dn).append(" ").append(e.getMessage());
             */

            // we avoid throwing an exception here since we throw that exception
            // in a one level above this.
            if (debug) {
                log.debug("Authentication failed " + e);
                log.debug("Clearing cache for DN: " + dn);
            }
            if (userName != null) {
//                removeFromUserCache(userName);
            }

        } finally {
            JNDIUtil.closeContext(cxt);
        }

        if (debug) {
            log.debug("User: " + dn + " is authenticated: " + isAuthed);
        }
        return isAuthed;
    }

    @Override
    protected String[] doGetExternalRoleListOfUser(String userName, String filter) throws UserStoreException {
        // Get the effective search base
        String searchBase = this.getEffectiveSearchBase(false);
        return getLDAPRoleListOfUser(userName, filter, searchBase, false);
    }

    /**
     * This method will check whether back link support is enabled and will
     * return the effective
     * search base. Read http://www.frickelsoft.net/blog/?p=130 for more
     * details.
     *
     * @param shared whether share search based or not
     * @return The search base based on back link support. If back link support
     * is enabled this will
     * return user search base, else group search base.
     */
    protected String getEffectiveSearchBase(boolean shared) {

        String backLinksEnabled =
                realmConfig.getUserStoreProperty(LDAPConstants.BACK_LINKS_ENABLED);
        boolean isBackLinkEnabled = false;

        if (backLinksEnabled != null && !backLinksEnabled.equals("")) {
            isBackLinkEnabled = Boolean.parseBoolean(backLinksEnabled);
        }

        if (isBackLinkEnabled) {
            return realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        } else {
            if (shared) {
                return realmConfig.getUserStoreProperty(LDAPConstants.SHARED_GROUP_SEARCH_BASE);
            } else {
                return realmConfig.getUserStoreProperty(LDAPConstants.GROUP_SEARCH_BASE);
            }
        }

    }

    protected String[] getLDAPRoleListOfUser(String userName, String filter, String searchBase,
                                             boolean shared) throws UserStoreException {
        if (userName == null) {
            throw new UserStoreException("userName value is null.");
        }
        boolean debug = log.isDebugEnabled();
        List<String> list = new ArrayList<String>();
        /*
         * do not search REGISTRY_ANONNYMOUS_USERNAME or
         * REGISTRY_SYSTEM_USERNAME in LDAP because it
         * causes warn logs printed from embedded-ldap.
         */
//        if (readGroupsEnabled && (!UserCoreUtil.isRegistryAnnonymousUser(userName)) &&
//                (!UserCoreUtil.isRegistrySystemUser(userName))) {
//
//            SearchControls searchCtls = new SearchControls();
//            searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//
//            String memberOfProperty =
//                    realmConfig.getUserStoreProperty(LDAPConstants.MEMBEROF_ATTRIBUTE);
//            if (memberOfProperty != null && memberOfProperty.length() > 0) {
//                // TODO Handle active directory shared roles logics here
//
//                String userNameProperty =
//                        realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
//                String userSearchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_SEARCH_FILTER);
//                String searchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userName));
//
//                String binaryAttribute =
//                        realmConfig.getUserStoreProperty(LDAPConstants.LDAP_ATTRIBUTES_BINARY);
//                String primaryGroupId =
//                        realmConfig.getUserStoreProperty(LDAPConstants.PRIMARY_GROUP_ID);
//
//                String returnedAtts[] = {memberOfProperty};
//
//                if (binaryAttribute != null && primaryGroupId != null) {
//                    returnedAtts =
//                            new String[]{memberOfProperty, binaryAttribute, primaryGroupId};
//                }
//
//                searchCtls.setReturningAttributes(returnedAtts);
//
//                if (debug) {
//                    log.debug("Reading roles with the memberOfProperty Property: " + memberOfProperty);
//                }
//
//                if (binaryAttribute != null && primaryGroupId != null) {
//                    list =
//                            this.getAttributeListOfOneElementWithPrimarGroup(
//                                    searchBase,
//                                    searchFilter,
//                                    searchCtls,
//                                    binaryAttribute,
//                                    primaryGroupId,
//                                    userNameProperty,
//                                    memberOfProperty);
//                } else {
//                    // use cache
//                    LdapName ldn = getFromUserCache(userName);
//                    if (ldn != null) {
//                        searchBase = ldn.toString();
//                    } else {
//                        // create DN directly   but there is no way when multiple DNs are used. Need to improve letter
//                        String userDNPattern = realmConfig.getUserStoreProperty(LDAPConstants.USER_DN_PATTERN);
//                        if (userDNPattern != null && userDNPattern.trim().length() > 0
//                                && !userDNPattern.contains("#")) {
//                            searchBase = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));
//                        }
//                    }
//
//                    // get DNs of the groups to which this user belongs
//                    List<String> groupDNs = this.getListOfNames(searchBase, searchFilter,
//                            searchCtls, memberOfProperty, false);
//                    List<LdapName> groups = new ArrayList<>();
//                    for (String groupDN : groupDNs) {
//                        try {
//                            groups.add(new LdapName(groupDN));
//                        } catch (InvalidNameException e) {
//                            if (log.isDebugEnabled()) {
//                                log.debug("LDAP Name error :", e);
//                            }
//                        }
//                    }
//                    /*
//                     * to be compatible with AD as well, we need to do a search
//                     * over the groups and
//                     * find those groups' attribute value defined for group name
//                     * attribute and
//                     * return
//                     */
//                    list = this.getGroupNameAttributeValuesOfGroups(groups);
//                }
//            } else {
//
//                // Load normal roles with the user
//                String searchFilter;
//                String roleNameProperty;
//
//                if (shared) {
//                    searchFilter = realmConfig.
//                            getUserStoreProperty(LDAPConstants.SHARED_GROUP_NAME_LIST_FILTER);
//                    roleNameProperty =
//                            realmConfig.getUserStoreProperty(LDAPConstants.SHARED_GROUP_NAME_ATTRIBUTE);
//                } else {
//                    searchFilter = realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_LIST_FILTER);
//                    roleNameProperty =
//                            realmConfig.getUserStoreProperty(LDAPConstants.GROUP_NAME_ATTRIBUTE);
//                }
//
//                String membershipProperty =
//                        realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE);
//                String userDNPattern = realmConfig.getUserStoreProperty(LDAPConstants.USER_DN_PATTERN);
//                String nameInSpace;
//                if (userDNPattern != null && userDNPattern.trim().length() > 0 && !userDNPattern.contains("#")) {
//
//                    nameInSpace = MessageFormat.format(userDNPattern, escapeSpecialCharactersForDN(userName));
//                } else {
//                    nameInSpace = this.getNameInSpaceForUserName(userName);
//                }
//                // read the roles with this membership property
//
//                if (membershipProperty == null || membershipProperty.length() < 1) {
//                    throw new UserStoreException(
//                            "Please set member of attribute or membership attribute");
//                }
//
//                String membershipValue;
//                if (nameInSpace != null) {
//                    try {
//                        LdapName ldn = new LdapName(nameInSpace);
//                        if (MEMBER_UID.equals(realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE))) {
//                            // membership value of posixGroup is not DN of the user
//                            List rdns = ldn.getRdns();
//                            membershipValue = ((Rdn) rdns.get(rdns.size() - 1)).getValue().toString();
//                        } else {
//                            membershipValue = escapeLdapNameForFilter(ldn);
//                        }
//                    } catch (InvalidNameException e) {
//                        log.error("Error while creating LDAP name from: " + nameInSpace);
//                        throw new UserStoreException("Invalid naming exception for : " + nameInSpace, e);
//                    }
//                } else {
//                    return new String[0];
//                }
//
//                searchFilter =
//                        "(&" + searchFilter + "(" + membershipProperty + "=" + membershipValue + "))";
//                String returnedAtts[] = {roleNameProperty};
//                searchCtls.setReturningAttributes(returnedAtts);
//
//                if (debug) {
//                    log.debug("Reading roles with the membershipProperty Property: " + membershipProperty);
//                }
//
//                list = this.getListOfNames(searchBase, searchFilter, searchCtls, roleNameProperty, false);
//            }
//        } else if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
//            // returning a REGISTRY_ANONNYMOUS_ROLE_NAME for
//            // REGISTRY_ANONNYMOUS_USERNAME
//            list.add(UserCoreConstants.REGISTRY_ANONNYMOUS_ROLE_NAME);
//        }
//
//        String[] result = list.toArray(new String[list.size()]);
//
//        if (result != null) {
//            for (String rolename : result) {
//                log.debug("Found role: " + rolename);
//            }
//        }
//        todo
        return new String[0];
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

    /**
     * This method performs the additional level escaping for ldap search. In ldap search / and " characters
     * have to be escaped again
     * @param dn DN
     * @return composite name
     * @throws InvalidNameException failed to build composite name
     */
    protected Name escapeDNForSearch(String dn) throws InvalidNameException {
        // This is done to escape '/' which is not a LDAP special character but a JNDI special character.
        // Refer: https://bugs.java.com/bugdatabase/view_bug.do?bug_id=4307193
        return new CompositeName().add(dn);
    }

    @Override
    public boolean doAuthenticate(String username, String password) throws UserStoreException {
        return false;
    }

    @Override
    public String[] doGetRoleListOfUser(String username) throws UserStoreException {
        return new String[0];
    }

    @Override
    public boolean isAdmin(String username) throws UserStoreException {
        return false;
    }
}
