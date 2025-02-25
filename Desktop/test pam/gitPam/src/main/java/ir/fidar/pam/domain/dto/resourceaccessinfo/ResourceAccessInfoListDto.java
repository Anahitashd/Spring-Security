package ir.fidar.pam.domain.dto.resourceaccessinfo;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;

public class ResourceAccessInfoListDto extends FullAuditionReadDto {
   private String label;
   private String username;
   private String password;
   private String secretKey;
   private boolean editSharedInfoPrivileged;

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
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

   public String getSecretKey() {
      return this.secretKey;
   }

   public void setSecretKey(String secretKey) {
      this.secretKey = secretKey;
   }

   public boolean isEditSharedInfoPrivileged() {
      return this.editSharedInfoPrivileged;
   }

   public void setEditSharedInfoPrivileged(boolean editSharedInfoPrivileged) {
      this.editSharedInfoPrivileged = editSharedInfoPrivileged;
   }
}
