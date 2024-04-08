package org.wso2.ei.dashboard.user.store;

public interface UserStoreManager {

    /**
     * Authenticates a user with the given credentials.
     *
     * @param username The username of the user.
     * @param password The password of the user.
     * @return true if authentication is successful, false otherwise.
     */
    boolean authenticate(String username, String password);
}
