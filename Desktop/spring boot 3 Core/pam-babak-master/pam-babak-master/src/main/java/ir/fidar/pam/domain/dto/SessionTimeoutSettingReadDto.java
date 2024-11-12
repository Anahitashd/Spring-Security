package ir.fidar.pam.domain.dto;

import ir.fidar.core.domain.dto.crud.MutationOnlyReadDto;

public class SessionTimeoutSettingReadDto extends MutationOnlyReadDto {
   private int sshConnectionTimeout;
   private int rdpConnectionTimeout;
   private int vncConnectionTimeout;
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
