package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.MutationOnlySingletonBaseEntity;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.HttpMethod;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.authorization.model.annotations.SpecialPrivilege;
import ir.fidar.pam.domain.dto.SessionTimeoutSettingUpdateDto;
import ir.fidar.pam.service.impl.SessionTimeoutSettingCrudServiceImpl;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

@Secure(
   section = "SESSION_TIMEOUT",
   special = {@SpecialPrivilege(
      name = "MANAGEMENT",
      baseURLs = {"/api/settings/session-timeout"},
      allowedMethods = {HttpMethod.GET, HttpMethod.PUT}
   )}
)
@EnableAutoCrudLogging(
   singletonEntity = true,
   displayName = "Session Timeout Setting",
   crudServiceImpl = SessionTimeoutSettingCrudServiceImpl.class,
   createDto = SessionTimeoutSettingUpdateDto.class,
   updateDto = SessionTimeoutSettingUpdateDto.class
)
@Entity
@Table(
   name = "tb_session_timeout_setting"
)
public class SessionTimeoutSetting extends MutationOnlySingletonBaseEntity {
   @Min(
      value = 0L,
      message = "lt_min.sshConnectionTimeout"
   )
   @Max(
      value = 60L,
      message = "gt_max.sshConnectionTimeout"
   )
   private int sshConnectionTimeout;
   @Min(
      value = 0L,
      message = "lt_min.rdpConnectionTimeout"
   )
   @Max(
      value = 60L,
      message = "gt_max.rdpConnectionTimeout"
   )
   private int rdpConnectionTimeout;
   @Min(
      value = 0L,
      message = "lt_min.vncConnectionTimeout"
   )
   @Max(
      value = 60L,
      message = "gt_max.vncConnectionTimeout"
   )
   private int vncConnectionTimeout;
   @Min(
      value = 0L,
      message = "lt_min.telnetConnectionTimeout"
   )
   @Max(
      value = 60L,
      message = "gt_max.telnetConnectionTimeout"
   )
   private int telnetConnectionTimeout;
   private boolean reactiveSshByMouseMovement;
   private boolean reactiveTelnetByMouseMovement;

   public int getSshConnectionTimeout() {
      return this.sshConnectionTimeout;
   }

   public void setSshConnectionTimeout(int sshConnectionTimeout) {
      this.sshConnectionTimeout = sshConnectionTimeout;
   }

   public int getRdpConnectionTimeout() {
      return this.rdpConnectionTimeout;
   }

   public void setRdpConnectionTimeout(int rdpConnectionTimeout) {
      this.rdpConnectionTimeout = rdpConnectionTimeout;
   }

   public int getVncConnectionTimeout() {
      return this.vncConnectionTimeout;
   }

   public void setVncConnectionTimeout(int vncConnectionTimeout) {
      this.vncConnectionTimeout = vncConnectionTimeout;
   }

   public int getTelnetConnectionTimeout() {
      return this.telnetConnectionTimeout;
   }

   public void setTelnetConnectionTimeout(int telnetConnectionTimeout) {
      this.telnetConnectionTimeout = telnetConnectionTimeout;
   }

   public boolean isReactiveSshByMouseMovement() {
      return this.reactiveSshByMouseMovement;
   }

   public void setReactiveSshByMouseMovement(boolean reactiveByMouseMovement) {
      this.reactiveSshByMouseMovement = reactiveByMouseMovement;
   }

   public boolean isReactiveTelnetByMouseMovement() {
      return this.reactiveTelnetByMouseMovement;
   }

   public void setReactiveTelnetByMouseMovement(boolean reactiveTelnetByMouseMovement) {
      this.reactiveTelnetByMouseMovement = reactiveTelnetByMouseMovement;
   }
}
