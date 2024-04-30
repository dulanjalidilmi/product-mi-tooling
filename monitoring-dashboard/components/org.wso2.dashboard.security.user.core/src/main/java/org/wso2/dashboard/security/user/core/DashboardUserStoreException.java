package org.wso2.dashboard.security.user.core;

// todo this should be renamed to UserStoreException later
public class DashboardUserStoreException extends Exception {

    public DashboardUserStoreException() {
        super();
    }

    public DashboardUserStoreException(String message, Throwable cause) {
        super(message, cause);
    }

    public DashboardUserStoreException(String message) {
        super(message);
    }

    public DashboardUserStoreException(Throwable cause) {
        super(cause);
    }
}
