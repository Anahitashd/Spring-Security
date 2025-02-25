package ir.fidar.pam.domain.dto.connection;

public class RdpConnectionRemoteApplicationDetailsDto {
   private String name;
   private String workingDirectory;
   private String params;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getWorkingDirectory() {
      return this.workingDirectory;
   }

   public void setWorkingDirectory(String workingDirectory) {
      this.workingDirectory = workingDirectory;
   }

   public String getParams() {
      return this.params;
   }

   public void setParams(String params) {
      this.params = params;
   }
}
