package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.CredentialDetailsDto;

public class AccessRuleConnectionReadDto {
   private ConnectionInfoDto connection;
   private CredentialDetailsDto credential;
   private RdpConnectionRemoteApplicationDetailsDto remoteApplication;

   public ConnectionInfoDto getConnection() {
      return this.connection;
   }

   public void setConnection(ConnectionInfoDto connection) {
      this.connection = connection;
   }

   public CredentialDetailsDto getCredential() {
      return this.credential;
   }

   public void setCredential(CredentialDetailsDto credential) {
      this.credential = credential;
   }

   public RdpConnectionRemoteApplicationDetailsDto getRemoteApplication() {
      return this.remoteApplication;
   }

   public void setRemoteApplication(RdpConnectionRemoteApplicationDetailsDto remoteApplication) {
      this.remoteApplication = remoteApplication;
   }
}
