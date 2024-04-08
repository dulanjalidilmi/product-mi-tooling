mvn -s /Users/dulanjali/Documents/repos/settings_xml/umt_settings.xml clean install -Dmaven.test.skip=true;
unzip distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT.zip -d distribution/target;
./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh -debug 5005;

#./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh
#./distribution/target/wso2mi-dashboard-4.3.0-SNAPSHOT/bin/dashboard.sh -debug 5005;