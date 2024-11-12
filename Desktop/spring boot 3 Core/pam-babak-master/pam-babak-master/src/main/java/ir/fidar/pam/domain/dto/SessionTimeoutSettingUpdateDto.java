package ir.fidar.pam.domain.dto;

import ir.fidar.core.domain.dto.crud.CreateDto;
import ir.fidar.core.domain.dto.crud.UpdateDto;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public class SessionTimeoutSettingUpdateDto implements UpdateDto, CreateDto {
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

   public void setReactiveSshByMouseMovement(boolean reactiveSshByMouseMovement) {
      this.reactiveSshByMouseMovement = reactiveSshByMouseMovement;
   }

   public boolean isReactiveTelnetByMouseMovement() {
      return this.reactiveTelnetByMouseMovement;
   }

   public void setReactiveTelnetByMouseMovement(boolean reactiveTelnetByMouseMovement) {
      this.reactiveTelnetByMouseMovement = reactiveTelnetByMouseMovement;
   }
}
