package org.wso2.micro.integrator.dashboard.backend.rest.model;

import javax.validation.constraints.*;
import javax.validation.Valid;


import io.swagger.annotations.*;
import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;


public class HeatbeatSignalRequestBody   {
  private @Valid String groupId = null;
  private @Valid String nodeId = null;
  private @Valid Integer interval = null;

  /**
   **/
  public HeatbeatSignalRequestBody groupId(String groupId) {
    this.groupId = groupId;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("groupId")

  public String getGroupId() {
    return groupId;
  }
  public void setGroupId(String groupId) {
    this.groupId = groupId;
  }

  /**
   **/
  public HeatbeatSignalRequestBody nodeId(String nodeId) {
    this.nodeId = nodeId;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("nodeId")

  public String getNodeId() {
    return nodeId;
  }
  public void setNodeId(String nodeId) {
    this.nodeId = nodeId;
  }

  /**
   **/
  public HeatbeatSignalRequestBody interval(Integer interval) {
    this.interval = interval;
    return this;
  }

  
  @ApiModelProperty(value = "")
  @JsonProperty("interval")

  public Integer getInterval() {
    return interval;
  }
  public void setInterval(Integer interval) {
    this.interval = interval;
  }


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    HeatbeatSignalRequestBody heatbeatSignalRequestBody = (HeatbeatSignalRequestBody) o;
    return Objects.equals(groupId, heatbeatSignalRequestBody.groupId) &&
        Objects.equals(nodeId, heatbeatSignalRequestBody.nodeId) &&
        Objects.equals(interval, heatbeatSignalRequestBody.interval);
  }

  @Override
  public int hashCode() {
    return Objects.hash(groupId, nodeId, interval);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class HeatbeatSignalRequestBody {\n");
    
    sb.append("    groupId: ").append(toIndentedString(groupId)).append("\n");
    sb.append("    nodeId: ").append(toIndentedString(nodeId)).append("\n");
    sb.append("    interval: ").append(toIndentedString(interval)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(java.lang.Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }
}
