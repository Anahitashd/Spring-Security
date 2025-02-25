package ir.fidar.pam.domain.dto.connection.details;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;
import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintDetailsDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.dto.credential.details.CredentialDetailsDto;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import java.util.List;

@JsonTypeInfo(
   use = Id.CLASS,
   property = "type"
)
@JsonSubTypes({@Type(SshConnectionDetailsDto.class), @Type(RdpConnectionDetailsDto.class), @Type(VncConnectionDetailsDto.class), @Type(TelnetConnectionDetailsDto.class)})
public class ConnectionDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private ConnectionType type;
   private String name;
   private String ipAddress;
   private int port;
   private List<CredentialDetailsDto> credentials;
   private boolean clipboard;
   private FileTransferMode fileTransferMode;
   private int maximumConcurrentSessions;
   private int maximumConcurrentSessionsPerUser;
   private Integer transparentPort;
   private List<BannerDetailsDto> banners;
   private List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints;
   private AccessibilityTimePeriodConstraintDetailsDto accessibilityTimePeriodConstraint;
   private List<ConnectionGroupInfoDto> connectionGroups;

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getIpAddress() {
      return this.ipAddress;
   }

   public void setIpAddress(String ipAddress) {
      this.ipAddress = ipAddress;
   }

   public int getPort() {
      return this.port;
   }

   public void setPort(int port) {
      this.port = port;
   }

   public List<CredentialDetailsDto> getCredentials() {
      return this.credentials;
   }

   public void setCredentials(List<CredentialDetailsDto> credentials) {
      this.credentials = credentials;
   }

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public int getMaximumConcurrentSessions() {
      return this.maximumConcurrentSessions;
   }

   public void setMaximumConcurrentSessions(int maximumConcurrentSessions) {
      this.maximumConcurrentSessions = maximumConcurrentSessions;
   }

   public int getMaximumConcurrentSessionsPerUser() {
      return this.maximumConcurrentSessionsPerUser;
   }

   public void setMaximumConcurrentSessionsPerUser(int maximumConcurrentSessionsPerUser) {
      this.maximumConcurrentSessionsPerUser = maximumConcurrentSessionsPerUser;
   }

   public Integer getTransparentPort() {
      return this.transparentPort;
   }

   public void setTransparentPort(Integer transparentPort) {
      this.transparentPort = transparentPort;
   }

   public List<BannerDetailsDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerDetailsDto> banners) {
      this.banners = banners;
   }

   public List<SessionInputConstraintViolationHandlerDetailsDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraintDetailsDto getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraintDetailsDto accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }

   public List<ConnectionGroupInfoDto> getConnectionGroups() {
      return this.connectionGroups;
   }

   public void setConnectionGroups(List<ConnectionGroupInfoDto> connectionGroups) {
      this.connectionGroups = connectionGroups;
   }
}
