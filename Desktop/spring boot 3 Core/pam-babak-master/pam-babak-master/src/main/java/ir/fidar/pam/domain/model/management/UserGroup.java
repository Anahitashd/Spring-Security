package ir.fidar.pam.domain.model.management;

import ir.fidar.core.domain.dto.management.usergroup.UserGroupCreateDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupUpdateDto;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.service.impl.management.UserGroupCrudServiceImpl;
import java.util.Set;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

@EnableAutoCrudLogging(
   displayName = "User Group",
   crudServiceImpl = UserGroupCrudServiceImpl.class,
   createDto = UserGroupCreateDto.class,
   updateDto = UserGroupUpdateDto.class,
   uniquePropertyName = "name"
)
@Entity
@Table(
   name = "tb_user_group"
)
@DiscriminatorValue("1")
public class UserGroup extends ir.fidar.core.domain.model.management.UserGroup {
   @ManyToMany(
      mappedBy = "userGroups",
      fetch = FetchType.LAZY
   )
   private Set<AccessRule> accessRules;
   @ManyToMany(
      mappedBy = "userGroups",
      fetch = FetchType.LAZY
   )
   private Set<CaptureRule> captureRules;

   public Set<AccessRule> getAccessRules() {
      return this.accessRules;
   }

   public Set<CaptureRule> getCaptureRules() {
      return this.captureRules;
   }

   @Override
   public int hashCode() {
      return super.hashCode();
   }

   @Override
   public boolean equals(Object obj) {
      return super.equals(obj);
   }
}
