Running WSO2 Integration Control Plane as a Windows Service
------------------------------------------------

1. Download the latest stable version of YAJSW from the project home page. (http://yajsw.sourceforge.net/)
2. Unzip the YAJSW archive and place the provided wrapper.conf file (this directory) inside <YAJSW.Home.Dir>/conf.
3. Set 'java_home' and 'wso2_integration_control_plane_home' environment properties
4. Start the product as a windows service. (batch scripts are found under <YAJSW.Home.Dir>/bat)