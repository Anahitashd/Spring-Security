package ir.fidar.pam.domain.dto.accessrule;

public class ConnectionSpecialSetting {
   private String connection;
   private String credential;
   private String rdpRemoteApplication;

   public String getConnection() {
      return this.connection;
   }

   public void setConnection(String connection) {
      this.connection = connection;
   }

   public String getCredential() {
      return this.credential;
   }

   public void setCredential(String credential) {
      this.credential = credential;
   }

   public String getRdpRemoteApplication() {
      return this.rdpRemoteApplication;
   }

   public void setRdpRemoteApplication(String rdpRemoteApplication) {
      this.rdpRemoteApplication = rdpRemoteApplication;
   }
}
