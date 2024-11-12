package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.util.filter.annotation.FilterPropertyMapper;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.converter.attribbute.CaptureStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import java.util.Set;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Secure(
   section = "CAPTURE",
   crud = @CrudPrivilege(
      baseURLs = {"/api/captures/*", "/api/captures/*/record-file", "/api/captures/*/convert-to-video", "/api/captures/*/images", "/api/connections/*/capture-rules/privileges", "/api/captures/*/transferred-files/*", "/api/captures/*/input-constraint-violations", "/api/captures/*/key-events", "/api/captures/*/key-events/download", "/api/captures/*/transferred-clipboards", "/api/captures/*/executed-commands", "/api/captures/*/check-integrity", "/api/transparent-captures", "/api/transparent-captures/*/video-id", "/api/transparent-captures/*/download-video"},
      requests = {CrudRequest.READ}
   )
)
@Entity
@Table(
   name = "tb_capture"
)
public class Capture extends BaseEntity {
   @NotBlank(
      message = "blank.sessionId"
   )
   private String sessionId;
   @NotBlank(
      message = "blank.sessionId"
   )
   private String accessRuleUuid;
   @NotNull(
      message = "null.status"
   )
   @Convert(
      converter = CaptureStatusConverter.class
   )
   private CaptureStatus status;
   @Min(
      value = 0L,
      message = "lt_min.startTime"
   )
   private long startTime;
   @Min(
      value = 0L,
      message = "lt_min.endTime"
   )
   private long endTime;
   @NotBlank(
      message = "blank.owner"
   )
   private String owner;
   @NotNull(
      message = "null.type"
   )
   @Convert(
      converter = ConnectionTypeConverter.class
   )
   private ConnectionType type;
   @NotBlank(
      message = "blank.connectionName"
   )
   private String connectionName;
   @NotBlank(
      message = "blank.connectionIpAddress"
   )
   private String connectionIpAddress;
   @NotNull(
      message = "null.connectionPort"
   )
   private int connectionPort;
   @NotBlank(
      message = "blank.bridgeName"
   )
   private String bridgeName;
   @NotBlank(
      message = "blank.bridgeIpAddress"
   )
   private String bridgeIpAddress;
   private String credentialLabel;
   @NotNull(
      message = "null.activeFileTransferMode"
   )
   @Convert(
      converter = FileTransferModeConverter.class
   )
   private FileTransferMode activeFileTransferMode;
   private boolean hadClipboard;
   @OneToMany(
      fetch = FetchType.LAZY,
      mappedBy = "capture",
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @FilterPropertyMapper(
      property = "input-const.",
      isRelationalField = true
   )
   private Set<SessionInputConstraintViolationIncident> sessionInputConstraintViolationIncidents;
   @OneToMany(
      fetch = FetchType.LAZY,
      mappedBy = "capture",
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @FilterPropertyMapper(
      property = "transferred-file.",
      isRelationalField = true
   )
   private Set<SessionTransferredFile> sessionTransferredFiles;
   @OneToOne(
      fetch = FetchType.EAGER,
      mappedBy = "capture",
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   private CaptureClientInformation clientInformation;
   @OneToMany(
      fetch = FetchType.EAGER,
      mappedBy = "capture",
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   private Set<CaptureTransferredClipboard> clipboards;
   @OneToMany(
      fetch = FetchType.LAZY,
      mappedBy = "capture",
      cascade = {CascadeType.PERSIST, CascadeType.MERGE}
   )
   @FilterPropertyMapper(
      property = "exec-cmd.",
      isRelationalField = true
   )
   private Set<CaptureExecutedCommand> commands;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String sessionId) {
      this.sessionId = sessionId;
   }

   public String getAccessRuleUuid() {
      return this.accessRuleUuid;
   }

   public void setAccessRuleUuid(String accessRuleId) {
      this.accessRuleUuid = accessRuleId;
   }

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public CaptureStatus getStatus() {
      return this.status;
   }

   public void setStatus(CaptureStatus status) {
      this.status = status;
   }

   public long getStartTime() {
      return this.startTime;
   }

   public void setStartTime(long startTime) {
      this.startTime = startTime;
   }

   public long getEndTime() {
      return this.endTime;
   }

   public void setEndTime(long endTime) {
      this.endTime = endTime;
   }

   public String getOwner() {
      return this.owner;
   }

   public void setOwner(String owner) {
      this.owner = owner;
   }

   public String getBridgeName() {
      return this.bridgeName;
   }

   public void setBridgeName(String bridgeName) {
      this.bridgeName = bridgeName;
   }

   public String getBridgeIpAddress() {
      return this.bridgeIpAddress;
   }

   public void setBridgeIpAddress(String bridgeIpAddress) {
      this.bridgeIpAddress = bridgeIpAddress;
   }

   public String getConnectionName() {
      return this.connectionName;
   }

   public void setConnectionName(String connectionName) {
      this.connectionName = connectionName;
   }

   public String getConnectionIpAddress() {
      return this.connectionIpAddress;
   }

   public void setConnectionIpAddress(String connectionIpAddress) {
      this.connectionIpAddress = connectionIpAddress;
   }

   public int getConnectionPort() {
      return this.connectionPort;
   }

   public void setConnectionPort(int connectionPort) {
      this.connectionPort = connectionPort;
   }

   public String getCredentialLabel() {
      return this.credentialLabel;
   }

   public void setCredentialLabel(String credentialLabel) {
      this.credentialLabel = credentialLabel;
   }

   public FileTransferMode getActiveFileTransferMode() {
      return this.activeFileTransferMode;
   }

   public void setActiveFileTransferMode(FileTransferMode activeFileTransferMode) {
      this.activeFileTransferMode = activeFileTransferMode;
   }

   public boolean isHadClipboard() {
      return this.hadClipboard;
   }

   public void setHadClipboard(boolean hadClipboard) {
      this.hadClipboard = hadClipboard;
   }

   public Set<SessionInputConstraintViolationIncident> getSessionInputConstraintViolationIncidents() {
      return this.sessionInputConstraintViolationIncidents;
   }

   public void setSessionInputConstraintViolationIncidents(Set<SessionInputConstraintViolationIncident> sessionInputConstraintViolationIncidents) {
      this.sessionInputConstraintViolationIncidents = sessionInputConstraintViolationIncidents;
   }

   public Set<SessionTransferredFile> getSessionTransferredFiles() {
      return this.sessionTransferredFiles;
   }

   public void setSessionTransferredFiles(Set<SessionTransferredFile> sessionTransferredFiles) {
      this.sessionTransferredFiles = sessionTransferredFiles;
   }

   public CaptureClientInformation getClientInformation() {
      return this.clientInformation;
   }

   public void setClientInformation(CaptureClientInformation clientInformation) {
      this.clientInformation = clientInformation;
   }

   public Set<CaptureTransferredClipboard> getClipboards() {
      return this.clipboards;
   }

   public void setClipboards(Set<CaptureTransferredClipboard> clipboards) {
      this.clipboards = clipboards;
   }

   public Set<CaptureExecutedCommand> getCommands() {
      return this.commands;
   }

   public void setCommands(Set<CaptureExecutedCommand> commands) {
      this.commands = commands;
   }
}
