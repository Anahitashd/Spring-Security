package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationIncidentDetailsDto;
import ir.fidar.pam.domain.dto.SessionTransferredFileDetailsDto;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import java.util.List;

public class CaptureDetailsDto implements DetailsDto {
   private String sessionId;
   private CaptureStatus status;
   private long startTime;
   private long endTime;
   private String owner;
   private ConnectionType type;
   private String connectionName;
   private String connectionIpAddress;
   private int connectionPort;
   private String bridgeName;
   private String bridgeIpAddress;
   private String credentialLabel;
   private FileTransferMode activeFileTransferMode;
   private boolean hadClipboard;
   private List<SessionInputConstraintViolationIncidentDetailsDto> sessionInputConstraintViolationIncidents;
   private List<SessionTransferredFileDetailsDto> sessionTransferredFiles;
   private CaptureClientInformationDetailsDto clientInformation;
   private long videoSize;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String sessionId) {
      this.sessionId = sessionId;
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

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
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

   public List<SessionInputConstraintViolationIncidentDetailsDto> getSessionInputConstraintViolationIncidents() {
      return this.sessionInputConstraintViolationIncidents;
   }

   public void setSessionInputConstraintViolationIncidents(List<SessionInputConstraintViolationIncidentDetailsDto> sessionInputConstraintViolationIncidents) {
      this.sessionInputConstraintViolationIncidents = sessionInputConstraintViolationIncidents;
   }

   public List<SessionTransferredFileDetailsDto> getSessionTransferredFiles() {
      return this.sessionTransferredFiles;
   }

   public void setSessionTransferredFiles(List<SessionTransferredFileDetailsDto> sessionTransferredFiles) {
      this.sessionTransferredFiles = sessionTransferredFiles;
   }

   public CaptureClientInformationDetailsDto getClientInformation() {
      return this.clientInformation;
   }

   public void setClientInformation(CaptureClientInformationDetailsDto clientInformation) {
      this.clientInformation = clientInformation;
   }

   public long getVideoSize() {
      return this.videoSize;
   }

   public void setVideoSize(long videoSize) {
      this.videoSize = videoSize;
   }
}
