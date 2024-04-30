package org.wso2.dashboard.security.user.core;

public class UserStoreConstants {
    public static final String DEFAULT_LDAP_USERSTORE_MANAGER =
            "org.wso2.dashboard.security.user.core.ldap.ReadOnlyLDAPUserStoreManager";
    public static final String DEFAULT_JDBC_USERSTORE_MANAGER =
            "org.wso2.dashboard.security.user.core.jdbc.JDBCUserStoreManager";
//    todo discuss DOMAIN_SEPARATOR
    public static String DOMAIN_SEPARATOR = "/";
    public static final String PRIMARY_DEFAULT_DOMAIN_NAME = "PRIMARY";
}
