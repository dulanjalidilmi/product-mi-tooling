package org.wso2.dashboard.security.user.core;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.micro.integrator.security.user.api.RealmConfiguration;
import org.wso2.micro.integrator.security.user.api.UserStoreException;
import org.wso2.micro.integrator.security.user.core.UserRealm;
import org.wso2.micro.integrator.security.user.core.claim.ClaimManager;
import org.wso2.micro.integrator.security.user.core.profile.ProfileConfigurationManager;

import java.lang.reflect.Constructor;
import java.util.Hashtable;
import java.util.Map;

public class DashboardSecurityUtils {
    private static Log log = LogFactory.getLog(DashboardSecurityUtils.class);

    public static Object createObjectWithOptions(String className, RealmConfiguration realmConfig) throws UserStoreException {
        /*
            Since different User Store managers contain constructors requesting different sets of arguments, this method
            tries to invoke the constructor with different combinations of arguments
         */
        Class[] initClassOpt0 = new Class[]{RealmConfiguration.class, Map.class, ClaimManager.class,
                ProfileConfigurationManager.class, UserRealm.class, Integer.class, boolean.class};
        Object[] initObjOpt0 = new Object[]{realmConfig, new Hashtable<String, Object>(), null, null, null, -1234, true};
        Class[] initClassOpt1 = new Class[]{RealmConfiguration.class, ClaimManager.class, ProfileConfigurationManager.class};
        Object[] initObjOpt1 = new Object[]{realmConfig, null, null};
        Class[] initClassOpt2 = new Class[]{RealmConfiguration.class, int.class};
        Object[] initObjOpt2 = new Object[]{realmConfig, -1234};
        Class[] initClassOpt3 = new Class[]{RealmConfiguration.class};
        Object[] initObjOpt3 = new Object[]{realmConfig};
        Class[] initClassOpt4 = new Class[]{};
        Object[] initObjOpt4 = new Object[]{};
        try {
            Class clazz = Class.forName(className);
            Object newObject = null;
            if (log.isDebugEnabled()) {
                log.debug("Start initializing the UserStoreManager class with first option");
            }

            Constructor constructor;
            try {
                constructor = clazz.getConstructor(initClassOpt0);
                newObject = constructor.newInstance(initObjOpt0);
                return newObject;
            } catch (NoSuchMethodException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " trying second option");
                }
            }

            try {
                constructor = clazz.getConstructor(initClassOpt1);
                newObject = constructor.newInstance(initObjOpt1);
                return newObject;
            } catch (NoSuchMethodException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " trying second option");
                }
            }

            try {
                constructor = clazz.getConstructor(initClassOpt2);
                newObject = constructor.newInstance(initObjOpt2);
                return newObject;
            } catch (NoSuchMethodException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " using the option 2");
                }
            }

            try {
                constructor = clazz.getConstructor(initClassOpt3);
                newObject = constructor.newInstance(initObjOpt3);
                return newObject;
            } catch (NoSuchMethodException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " using the option 3");
                }
            }

            try {
                constructor = clazz.getConstructor(initClassOpt4);
                newObject = constructor.newInstance(initObjOpt4);
                return newObject;
            } catch (NoSuchMethodException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannont initialize " + className + " using the option 4");
                }
                throw new UserStoreException(e.getMessage(), e);
            }
        } catch (Throwable e) {
            if (log.isDebugEnabled()) {
                log.debug("Cannot create " + className, e);
            }
            throw new UserStoreException(e.getMessage() + "Type " + e.getClass(), e);
        }
    }
}
