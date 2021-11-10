/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *
 */

package org.wso2.ei.dashboard.core.db.manager;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.wso2.ei.dashboard.core.commons.Constants;
import org.wso2.ei.dashboard.core.exception.DashboardServerException;
import org.wso2.ei.dashboard.core.rest.delegates.heartbeat.HeartbeatObject;
import org.wso2.ei.dashboard.core.rest.model.ArtifactDetails;
import org.wso2.ei.dashboard.core.rest.model.Artifacts;
import org.wso2.ei.dashboard.core.rest.model.ArtifactsInner;
import org.wso2.ei.dashboard.core.rest.model.GroupList;
import org.wso2.ei.dashboard.core.rest.model.NodeList;
import org.wso2.ei.dashboard.core.rest.model.NodeListInner;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.sql.DataSource;

/**
 * Performs jdbc operations.
 */
public final class JDBCDatabaseManager implements DatabaseManager {

    private static final Logger logger = LogManager.getLogger(JDBCDatabaseManager.class);
    private final DataSource dataSource;

    public JDBCDatabaseManager() {
        HikariConfig config = new HikariConfig();

        String databaseURL = Constants.DATABASE_URL.replace("\\", "\\\\");

        config.setJdbcUrl(databaseURL);
        config.setUsername(Constants.DATABASE_USERNAME);
        config.setPassword(Constants.DATABASE_PASSWORD);

        config.addDataSourceProperty("cachePrepStmts" , "true");
        config.addDataSourceProperty("prepStmtCacheSize" , "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit" , "2048");
        dataSource = new HikariDataSource(config);
    }

    @Override
    public boolean insertHeartbeat(HeartbeatObject heartbeat, String accessToken) {
        logger.info("inserting heartbeat into database: groupID: " + heartbeat.getGroupId() + " nodeid: " +
                    heartbeat.getNodeId());
        String query = "INSERT INTO HEARTBEAT VALUES (?,?,?,?,?,?);";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, heartbeat.getGroupId());
            statement.setString(2, heartbeat.getNodeId());
            statement.setInt(3, heartbeat.getInterval());
            statement.setString(4, heartbeat.getMgtApiUrl());
            statement.setString(5, String.valueOf(heartbeat.getTimestamp()));
            statement.setString(6, accessToken);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            logger.error("Error occurred while inserting heartbeat information. " + e.getMessage(),
                         e.getCause());
            throw new DashboardServerException("Error occurred while inserting heartbeat information.", e);
        }
    }

    @Override
    public boolean insertServerInformation(HeartbeatObject heartbeat, String serverInfo) {
        String query = "INSERT INTO SERVERS VALUES (?,?,?);";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, heartbeat.getGroupId());
            statement.setString(2, heartbeat.getNodeId());
            statement.setString(3, serverInfo);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while inserting server information of node : "
                                               + heartbeat.getNodeId() + " in group: " + heartbeat.getGroupId(), e);
        }
    }

    @Override
    public boolean insertArtifact(String groupId, String nodeId, String artifactType, String artifactName,
                                  String artifactDetails) {
        String query = "INSERT INTO " + getTableName(artifactType) + " VALUES (?,?,?,?);";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            statement.setString(3, artifactName);
            statement.setString(4, artifactDetails);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while inserting " + artifactName + " information.", e);
        }
    }

    @Override
    public GroupList fetchGroups() {
        String query = "SELECT DISTINCT GROUP_ID FROM HEARTBEAT;";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            GroupList groupList = new GroupList();
            ResultSet resultSet = statement.executeQuery();
            while (resultSet.next()) {
                groupList.add(resultSet.getString("GROUP_ID"));
            }
            logger.info("Group list size: " + groupList.size());
            return groupList;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred fetching groups.", e);
        }
    }

    @Override
    public NodeList fetchNodes(String groupId) {
        String query = "SELECT * FROM SERVERS WHERE GROUP_ID=?";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            NodeList nodeList = new NodeList();
            ResultSet resultSet = statement.executeQuery();
            while (resultSet.next()) {
                String nodeId = resultSet.getString("NODE_ID");
                String details = resultSet.getString("DETAILS");
                NodeListInner nodeListInner = new NodeListInner();
                nodeListInner.setNodeId(nodeId);
                nodeListInner.setDetails(details);
                nodeList.add(nodeListInner);
            }
            return nodeList;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred fetching servers.", e);
        }
    }

    @Override
    public Artifacts fetchArtifacts(String artifactType, String groupId, List<String> nodeList) {
        Artifacts artifacts = new Artifacts();

        String nodeSearch = "";
        String nodeSearchTmp = nodeSearch;
        nodeList.forEach(node-> nodeSearchTmp.concat("NODE_ID=? OR "));
        nodeSearch = nodeSearchTmp;

        for (int i = 0; i < nodeList.size(); i++) {
            nodeSearch = nodeSearch.concat("NODE_ID=? OR ");
        }
        if (!nodeSearch.equals("")) {
            nodeSearch = nodeSearch.substring(0, nodeSearch.length() - 4);
        }
        String tableName = getTableName(artifactType);
        String getDistinctNamesQuery = "SELECT DISTINCT NAME FROM " + tableName + " WHERE GROUP_ID=? "
                                       + "AND (" + nodeSearch + ");";
        String getDetailsQuery = "SELECT NODE_ID, DETAILS FROM " + tableName + " WHERE NAME=? AND GROUP_ID=? AND " +
                                  "(" + nodeSearch + ");";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(getDistinctNamesQuery);

        ) {
            statement.setString(1, groupId);
            for (int i = 0, j = 2; i < nodeList.size(); i++, j++) {
                statement.setString(j, nodeList.get(i));
            }
            ResultSet resultSet = statement.executeQuery();
            while (resultSet.next()) {
                ArtifactsInner artifactsInner = new ArtifactsInner();
                String artifactName = resultSet.getString("NAME");
                artifactsInner.setName(artifactName);
                List<ArtifactDetails> artifactDetails = getArtifactDetails(getDetailsQuery, artifactName, groupId,
                                                                           nodeList);
                artifactsInner.setNodes(artifactDetails);
                artifacts.add(artifactsInner);
            }
            return artifacts;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred fetching " + artifactType, e);
        }
    }

    @Override
    public String getMgtApiUrl(String groupId, String nodeId) {
        String query = "SELECT MGT_API_URL FROM HEARTBEAT WHERE GROUP_ID=? AND NODE_ID=?;";
        String mgtApiUrl = "";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);

        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                mgtApiUrl = resultSet.getString(1);
            }
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while retrieveTimestampOfRegisteredNode results.", e);
        }
        return mgtApiUrl;
    }

    @Override
    public String getAccessToken(String groupId, String nodeId) {
        String query = "SELECT ACCESS_TOKEN FROM HEARTBEAT WHERE GROUP_ID=? AND NODE_ID=?;";
        String accessToken = "";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                accessToken = resultSet.getString(1);
            }
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while retrieving access token of node: " + nodeId
                                               + " in group " + groupId, e);
        }
        return accessToken;
    }

    @Override
    public String getHeartbeatInterval(String groupId, String nodeId) {
        String query = "SELECT HERTBEAT_INTERVAL FROM HEARTBEAT WHERE GROUP_ID=? AND NODE_ID=?;";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            ResultSet resultSet = statement.executeQuery();
            resultSet.next();
            return resultSet.getString(1);
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while fetching heartbeat interval of group " + groupId
                                               + " node " + nodeId, e);
        }
    }


    @Override
    public boolean checkIfTimestampExceedsInitial(HeartbeatObject heartbeat, String initialTimestamp) {
        String query = "SELECT COUNT(*) FROM HEARTBEAT WHERE TIMESTAMP>? AND GROUP_ID=? AND NODE_ID=?;";
        boolean isExists = false;
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, initialTimestamp);
            statement.setString(2, heartbeat.getGroupId());
            statement.setString(3, heartbeat.getNodeId());
            ResultSet resultSet = statement.executeQuery();
            resultSet.next();
            if (resultSet.getInt(1) == 1) {
                isExists = true;
            }
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while retrieving next row.", e);
        }
        return isExists;
    }

    public String retrieveTimestampOfLastHeartbeat(String groupId, String nodeId) {
        String query = "SELECT TIMESTAMP FROM HEARTBEAT WHERE GROUP_ID = ? AND NODE_ID = ? ;";
        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            ResultSet resultSet = statement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getString(1);
            } else {
                return null;
            }
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while retrieveTimestampOfRegisteredNode results.", e);
        }
    }

    @Override
    public boolean updateHeartbeat(HeartbeatObject heartbeat) {
        String query = "UPDATE HEARTBEAT SET TIMESTAMP=? WHERE GROUP_ID=? AND NODE_ID=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, String.valueOf(heartbeat.getTimestamp()));
            statement.setString(2, heartbeat.getGroupId());
            statement.setString(3, heartbeat.getNodeId());
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while updating heartbeat information.", e);
        }
    }

    @Override
    public boolean updateAccessToken(String groupId, String nodeId, String accessToken) {
        String query = "UPDATE HEARTBEAT SET ACCESS_TOKEN=? WHERE GROUP_ID=? AND NODE_ID=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, accessToken);
            statement.setString(2, groupId);
            statement.setString(3, nodeId);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while updating access token.", e);
        }
    }

    @Override
    public boolean updateDetails(String artifactType, String artifactName, String groupId, String nodeId,
                                 String details) {
        String tableName = getTableName(artifactType);
        String query = "UPDATE " + tableName + " SET DETAILS=? WHERE GROUP_ID=? AND NODE_ID=? AND NAME=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, details);
            statement.setString(2, groupId);
            statement.setString(3, nodeId);
            statement.setString(4, artifactName);
            return statement.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while updating heartbeat information.", e);
        }
    }

    @Override
    public int deleteHeartbeat(HeartbeatObject heartbeat) {
        String query = "DELETE FROM HEARTBEAT WHERE GROUP_ID=? AND NODE_ID=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, heartbeat.getGroupId());
            statement.setString(2, heartbeat.getNodeId());
            return statement.executeUpdate();
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while deleting heartbeat information.", e);
        }
    }

    @Override
    public boolean deleteServerInformation(String groupId, String nodeId) {
        logger.debug("Deleting server information of node: " + nodeId + " in group : " + groupId);
        String query = "DELETE FROM SERVERS WHERE GROUP_ID=? AND NODE_ID=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            return (statement.executeUpdate() > 0);
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while deleting server information.", e);
        }
    }

    @Override
    public boolean deleteAllArtifacts(String artifactType, String groupId, String nodeId) {
        logger.debug("Deleting all " + artifactType + " in node: " + nodeId + " in group : " + groupId);
        String tableName = getTableName(artifactType);
        String query = "DELETE FROM " + tableName + " WHERE GROUP_ID=? AND NODE_ID=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            return (statement.executeUpdate() > 0);
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while deleting all " + artifactType +  " in node: "
                                               + nodeId + " in group : " + groupId, e);
        }
    }

    @Override
    public boolean deleteArtifact(String artifactType, String artifactName, String groupId, String nodeId) {

        logger.debug("Deleting " + artifactType + " : " + artifactName + " in node: " + nodeId +
                " in group : " + groupId);

        String tableName = getTableName(artifactType);

        String query = "DELETE FROM " + tableName + " WHERE GROUP_ID=? AND NODE_ID=? AND NAME=?;";

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(query);
        ) {
            statement.setString(1, groupId);
            statement.setString(2, nodeId);
            statement.setString(3, artifactName);
            return (statement.executeUpdate() > 0);
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while deleting " + artifactName, e);
        }
    }

    private List<ArtifactDetails> getArtifactDetails(String getServicesQuery, String artifactName, String groupId,
                                                     List<String> nodeList) {

        try (
                Connection con = getConnection();
                PreparedStatement statement = con.prepareStatement(getServicesQuery);
        ) {
            statement.setString(1, artifactName);
            statement.setString(2, groupId);
            for (int i = 0, j = 3; i < nodeList.size(); i++, j++) {
                statement.setString(j, nodeList.get(i));
            }
            ResultSet resultSet = statement.executeQuery();
            List<ArtifactDetails> artifactDetailsList = new ArrayList<>();
            while (resultSet.next()) {
                ArtifactDetails artifactDetails = new ArtifactDetails();
                String nodeId = resultSet.getString("NODE_ID");
                String details = resultSet.getString("DETAILS");

                artifactDetails.setNodeId(nodeId);
                artifactDetails.setDetails(details);
                artifactDetailsList.add(artifactDetails);
            }
            return artifactDetailsList;
        } catch (SQLException e) {
            throw new DashboardServerException("Error occurred while retrieving next row.", e);
        }
    }

    private String getTableName(String artifactType) {
        switch (artifactType) {
            case Constants.PROXY_SERVICES:
                return "PROXY_SERVICES";
            case Constants.ENDPOINTS:
                return "ENDPOINTS";
            case Constants.INBOUND_ENDPOINTS:
                return "INBOUND_ENDPOINTS";
            case Constants.MESSAGE_STORES:
                return "MESSAGE_STORES";
            case Constants.MESSAGE_PROCESSORS:
                return "MESSAGE_PROCESSORS";
            case Constants.APIS:
                return "APIS";
            case Constants.TEMPLATES:
                return "TEMPLATES";
            case Constants.SEQUENCES:
                return "SEQUENCES";
            case Constants.TASKS:
                return "TASKS";
            case Constants.LOCAL_ENTRIES:
                return "LOCAL_ENTRIES";
            case Constants.CONNECTORS:
                return "CONNECTORS";
            case Constants.CARBON_APPLICATIONS:
                return "CARBON_APPS";
            case Constants.DATA_SERVICES:
                return "DATA_SERVICES";
            default:
                throw new DashboardServerException("Artifact type " + artifactType + " is invalid.");
        }
    }

    private Connection getConnection() throws SQLException {
        return dataSource.getConnection();
    }
}
