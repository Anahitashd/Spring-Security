package ir.fidar.pam.domain.model.connection;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ValidIp;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Dependency;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.authorization.model.annotations.Source;
import ir.fidar.core.security.authorization.model.annotations.Target;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.service.impl.connection.ConnectionCrudServiceImpl;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.ManyToMany;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Secure(
   section = "CONNECTION",
   crud = @CrudPrivilege(
      baseURLs = {"/api/connections/*", "/api/connection-groups/*", "/api/connections/*/credentials", "/api/connections/*/services", "/api/connections/*/remote-applications"},
      requests = {CrudRequest.ALL}
   ),
   dependency = @Dependency(
      source = @Source(
         cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
      ),
      target = @Target(
         section = "SESSION_INPUT_CONSTRAINT",
         cruds = {CrudRequest.READ}
      )
   )
)
@EnableAutoCrudLogging(
   displayName = "Connection",
   crudServiceImpl = ConnectionCrudServiceImpl.class,
   createDto = ConnectionCreateDto.class,
   updateDto = ConnectionUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_connection"
)
public class Connection extends FullAuditionDescriptiveBaseEntity {
   @NotNull(
      message = "null.type"
   )
   @Convert(
      converter = ConnectionTypeConverter.class
   )
   protected ConnectionType type;
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   protected String name;
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
   @ManyToMany(
      mappedBy = "connections",
      fetch = FetchType.LAZY
   )
   private Set<ConnectionGroup> connectionGroups = new HashSet<>();
   @OneToMany(
      mappedBy = "connection",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   private Set<Credential> credentials = new HashSet<>();
   protected boolean clipboard;
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
      message = "lt_min.transparent_port"
   )
   @Max(
      value = 52000L,
      message = "gt_max.transparent_port"
   )
   private Integer transparentPort;
   @OneToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL},
      mappedBy = "connection"
   )
   private Set<Banner> banners = new HashSet<>();
   @OneToMany(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL},
      mappedBy = "connection"
   )
   private Set<SessionInputConstraintViolationHandler> sessionInputConstraints;
   @OneToOne(
      mappedBy = "connection",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   private AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint;
   @OneToMany(
      mappedBy = "connection",
      fetch = FetchType.LAZY
   )
   private Set<AccessRuleConnection> accessRules = new HashSet<>();
   @ManyToMany(
      fetch = FetchType.LAZY,
      mappedBy = "connections"
   )
   private Set<CaptureRule> captureRules = new HashSet<>();

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

   public Set<ConnectionGroup> getConnectionGroups() {
      return this.connectionGroups;
   }

   public Set<Credential> getCredentials() {
      return this.credentials;
   }

   public void addCredential(Credential credential) {
      if (!this.credentials.contains(credential)) {
         this.credentials.add(credential);
      }
   }

   public void removeCredential(Credential credential) {
      if (this.credentials.contains(credential)) {
         this.credentials.remove(credential);
      }
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

   public Set<Banner> getBanners() {
      return this.banners;
   }

   public void setBanners(Set<Banner> banners) {
      this.banners = banners;
   }

   public Set<SessionInputConstraintViolationHandler> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(Set<SessionInputConstraintViolationHandler> inputConstraints) {
      this.sessionInputConstraints = inputConstraints;
   }

   public AccessibilityTimePeriodConstraint getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }

   public Set<AccessRuleConnection> getAccessRules() {
      return this.accessRules;
   }

   public Set<CaptureRule> getCaptureRules() {
      return this.captureRules;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (!(o instanceof Connection)) {
         return false;
      } else {
         Connection that = (Connection)o;
         return this.name.equals(that.name);
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
