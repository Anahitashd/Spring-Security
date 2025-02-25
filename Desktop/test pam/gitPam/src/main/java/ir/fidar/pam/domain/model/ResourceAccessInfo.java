package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.management.User;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

@Entity
@Table(
   name = "tb_resource_access_info"
)
public class ResourceAccessInfo extends FullAuditionDescriptiveBaseEntity {
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
   @ManyToMany(
      fetch = FetchType.LAZY
   )
   @JoinTable(
      name = "tb_resource_access_info_user",
      joinColumns = {@JoinColumn(
         name = "resource_access_info_id"
      )},
      inverseJoinColumns = {@JoinColumn(
         name = "user_id"
      )}
   )
   private Set<User> usersToShare = new HashSet<>();
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

   public void setSecretKey(String key) {
      this.secretKey = key;
   }

   public Set<User> getUsersToShare() {
      return this.usersToShare;
   }

   public void addUserToShare(User user) {
      this.usersToShare.add(user);
   }

   public void removeUserToShare(User user) {
      this.usersToShare.remove(user);
   }

   public boolean isEditSharedInfoPrivileged() {
      return this.editSharedInfoPrivileged;
   }

   public void setEditSharedInfoPrivileged(boolean editByShareUserPrivileged) {
      this.editSharedInfoPrivileged = editByShareUserPrivileged;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         ResourceAccessInfo that = (ResourceAccessInfo)o;
         return this.label.equals(that.label);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.label);
   }
}
