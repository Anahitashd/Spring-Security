package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.FullAuditionSingletonBaseEntity;
import ir.fidar.core.security.authorization.model.HttpMethod;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.authorization.model.annotations.SpecialPrivilege;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Secure(
   section = "SYMMETRIC_KEY",
   special = {@SpecialPrivilege(
      name = "MANAGEMENT",
      baseURLs = {"/api/settings/symmetric-key"},
      allowedMethods = {HttpMethod.GET, HttpMethod.POST}
   )}
)
@Entity
@Table(
   name = "tb_symmetric_key"
)
public class SymmetricKey extends FullAuditionSingletonBaseEntity {
   @NotBlank(
      message = "blank.key"
   )
   @Size(
      max = 255,
      message = "gt_max.key"
   )
   private String symmetricKey;

   public String getSymmetricKey() {
      return this.symmetricKey;
   }

   public void setSymmetricKey(String key) {
      this.symmetricKey = key;
   }
}
