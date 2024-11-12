package ir.fidar.pam.domain.dto.report.useractivity;

public class UserSessionCountPerTypeDto {
   private int sshSessions;
   private int rdpSessions;
   private int vncSessions;
   private int telnetSessions;

   public int getSshSessions() {
      return this.sshSessions;
   }

   public void setSshSessions(int sshSessions) {
      this.sshSessions = sshSessions;
   }

   public int getRdpSessions() {
      return this.rdpSessions;
   }

   public void setRdpSessions(int rdpSessions) {
      this.rdpSessions = rdpSessions;
   }

   public int getVncSessions() {
      return this.vncSessions;
   }

   public void setVncSessions(int vncSessions) {
      this.vncSessions = vncSessions;
   }

   public int getTelnetSessions() {
      return this.telnetSessions;
   }

   public void setTelnetSessions(int telnetSessions) {
      this.telnetSessions = telnetSessions;
   }
}
