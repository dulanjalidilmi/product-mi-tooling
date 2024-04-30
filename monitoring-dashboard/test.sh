mvn -s /Users/dulanjali/Documents/repos/settings_xml/umt_settings.xml clean install -Dmaven.test.skip=true;
unzip distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT.zip -d distribution/target;
cp /Users/dulanjali/Desktop/dashboard-setup/sso/IS/wso2is-5.10.0/repository/resources/security/client-truststore.jks /Users/dulanjali/Documents/repos/product-mi-tooling/monitoring-dashboard/distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/conf/security/
cp /Users/dulanjali/Documents/repos/micro-integrator/distribution/target/wso2mi-4.3.0-SNAPSHOT/lib/mysql-connector-j-8.0.31.jar /Users/dulanjali/Documents/repos/product-mi-tooling/monitoring-dashboard/distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/lib
./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh -debug 5005;

# ./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh
#./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh -debug 5005;

