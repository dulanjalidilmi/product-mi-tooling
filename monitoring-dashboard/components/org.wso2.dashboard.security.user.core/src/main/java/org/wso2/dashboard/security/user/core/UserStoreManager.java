package org.wso2.dashboard.security.user.core;

import org.wso2.micro.integrator.security.user.core.UserStoreException;

public interface UserStoreManager {
//    protected RealmConfiguration realmConfig = null;

    /**
     * Authenticates a user with the given credentials.
     *
     * @param username The username of the user.
     * @param password The password of the user.
     * @return true if authentication is successful, false otherwise.
     */
    boolean doAuthenticate(String username, String password) throws UserStoreException;

    String[] doGetRoleListOfUser(String username) throws UserStoreException;

    boolean isAdmin(String username) throws UserStoreException;
}