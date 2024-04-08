package org.wso2.ei.dashboard.user.store;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to store user store configs.
 */
public class UserInfo {

    private char[] password;
    private List<String> groups;

    public UserInfo(char[] password, List<String> groups) {
        this.password = password;
        this.groups = groups;
    }

    public char[] getPassword() {
        return password;
    }

    // todo why char[]
    public void setPassword(char[] password) {
        this.password = password;
    }

    public List<String> getGroups() {
        return groups;
    }

    public void setGroups(List<String> groups) {
        this.groups = groups;
    }
}
