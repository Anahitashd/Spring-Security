package ir.fidar.pam.domain.dto.connection.create;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ReachableHost;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.credential.create.CredentialCreateDto;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.constraint.SessionInputConstraintUniqueRegexInList;
import java.util.List;
import javax.validation.Valid;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@JsonTypeInfo(
   use = Id.NAME,
   include = As.PROPERTY,
   property = "type",
   visible = true
)
@JsonSubTypes({@Type(
      value = SshConnectionCreateDto.class,
      name = "SSH"
   ), @Type(
      value = RdpConnectionCreateDto.class,
      name = "RDP"
   ), @Type(
      value = VncConnectionCreateDto.class,
      name = "VNC"
   ), @Type(
      value = TelnetConnectionCreateDto.class,
      name = "TELNET"
   )})
@ReachableHost(
   message = "unreachable_host",
   ipAddressProperty = "ipAddress",
   portProperty = "port",
   targetClass = ConnectionCreateDto.class
)
public class ConnectionCreateDto extends AbstractDescriptiveCreateDto {
   @NotNull(
      message = "null.type"
   )
   private ConnectionType type;
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @NotBlank(
      message = "blank.ipAddress"
   )
   @ValidIp
   @XssProtected
   private String ipAddress;
   @Min(
      value = 1L,
      message = "lt_min.port"
   )
   @Max(
      value = 65535L,
      message = "gt_max.port"
   )
   private int port;
   private List<CredentialCreateDto> credentials;
   private boolean clipboard;
   @Min(
      value = 0L,
      message = "lt_min.maximumConcurrentSessions"
   )
   @Max(
      value = 500L,
      message = "gt_max.maximumConcurrentSessions"
   )
   private int maximumConcurrentSessions;
   @Min(
      value = 0L,
      message = "lt_min.maximumConcurrentSessionsPerUser"
   )
   @Max(
      value = 500L,
      message = "gt_max.maximumConcurrentSessionsPerUser"
   )
   private int maximumConcurrentSessionsPerUser;
   @Min(
      value = 50000L,
      message = "lt_min.transparentPort"
   )
   @Max(
      value = 52000L,
      message = "gt_max.transparentPort"
   )
   private Integer transparentPort;
   private List<BannerCreateDto> banners;
   @SessionInputConstraintUniqueRegexInList(
      message = "dup_regex.sessionInputConstraints"
   )
   private List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints;
   @Valid
   private AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint;

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

   public List<CredentialCreateDto> getCredentials() {
      return this.credentials;
   }

   public void setCredentials(List<CredentialCreateDto> credentials) {
      this.credentials = credentials;
   }

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
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

   public List<BannerCreateDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerCreateDto> banners) {
      this.banners = banners;
   }

   public List<SessionInputConstraintViolationHandlerCreateDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraintCreateDto getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }
}
