package org.wso2.dashboard.security.user.core;

/**
 * This class is used to store user store configs.
 */
public class UserInfo {

    private char[] password;
    private boolean isAdmin;

    public UserInfo(char[] password, boolean isAdmin) {
        this.password = password;
        this.isAdmin = isAdmin;
    }

    public char[] getPassword() {
        return password;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }

    public boolean isAdmin() {
        return isAdmin;
    }

    public void setIsAdmin(boolean isAdmin) {
        this.isAdmin = isAdmin;
    }
}