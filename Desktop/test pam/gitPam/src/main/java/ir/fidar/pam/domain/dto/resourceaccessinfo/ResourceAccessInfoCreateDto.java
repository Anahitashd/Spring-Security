package ir.fidar.pam.domain.dto.resourceaccessinfo;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import java.util.Set;
import javax.validation.constraints.NotBlank;

public class ResourceAccessInfoCreateDto extends AbstractDescriptiveCreateDto {
   @NotBlank(
      message = "blank.label"
   )
   @ValidName
   @XssProtected
   private String label;
   @XssProtected
   private String username;
   private String password;
   private String secretKey;
   private Set<String> usersToShare;
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

   public Set<String> getUsersToShare() {
      return this.usersToShare;
   }

   public void setUsersToShare(Set<String> usersToShare) {
      this.usersToShare = usersToShare;
   }

   public boolean isEditSharedInfoPrivileged() {
      return this.editSharedInfoPrivileged;
   }

   public void setEditSharedInfoPrivileged(boolean editSharedInfoPrivileged) {
      this.editSharedInfoPrivileged = editSharedInfoPrivileged;
   }
}
