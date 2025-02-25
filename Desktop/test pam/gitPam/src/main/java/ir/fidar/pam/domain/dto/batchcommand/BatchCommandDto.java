package ir.fidar.pam.domain.dto.batchcommand;

import javax.validation.constraints.NotBlank;

public class BatchCommandDto {
   @NotBlank(
      message = "blank.command"
   )
   private String command;
   @NotBlank(
      message = "blank.label"
   )
   private String label;
   @NotBlank(
      message = "blank.connectionName"
   )
   private String connectionName;
   @NotBlank(
      message = "blank.bridgeName"
   )
   private String bridgeName;
   private String credentialLabel;
   private String username;
   private String password;

   public String getCommand() {
      return this.command;
   }

   public void setCommand(String command) {
      this.command = command;
   }

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
   }

   public String getConnectionName() {
      return this.connectionName;
   }

   public void setConnectionName(String connectionName) {
      this.connectionName = connectionName;
   }

   public String getBridgeName() {
      return this.bridgeName;
   }

   public void setBridgeName(String bridgeName) {
      this.bridgeName = bridgeName;
   }

   public String getCredentialLabel() {
      return this.credentialLabel;
   }

   public void setCredentialLabel(String credentialLabel) {
      this.credentialLabel = credentialLabel;
   }

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }

   public String getPassword() {
      return this.password;
   }

   public void setPassword(String password) {
      this.password = password;
   }
}
