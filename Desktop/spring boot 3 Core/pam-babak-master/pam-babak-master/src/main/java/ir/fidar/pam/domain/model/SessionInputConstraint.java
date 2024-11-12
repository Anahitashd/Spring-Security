package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.FullAuditionDescriptiveBaseEntity;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintCreateDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintUpdateDto;
import ir.fidar.pam.service.impl.SessionInputConstraintCrudServiceImpl;
import java.util.Objects;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Secure(
   section = "SESSION_INPUT_CONSTRAINT",
   crud = @CrudPrivilege(
      baseURLs = {"/api/session-input-constraints/*"},
      requests = {CrudRequest.ALL}
   )
)
@EnableAutoCrudLogging(
   displayName = "Session Input Constraint",
   crudServiceImpl = SessionInputConstraintCrudServiceImpl.class,
   createDto = SessionInputConstraintCreateDto.class,
   updateDto = SessionInputConstraintUpdateDto.class,
   uniquePropertyName = "Name"
)
@Entity
@Table(
   name = "tb_session_input_constraint"
)
public class SessionInputConstraint extends FullAuditionDescriptiveBaseEntity {
   @ValidName
   @Size(
      max = 48,
      message = "gt_name.name"
   )
   @XssProtected
   private String name;
   @NotBlank(
      message = "blank.regex"
   )
   @Size(
      max = 255,
      message = "gt_max.regex"
   )
   private String regex;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getRegex() {
      return this.regex;
   }

   public void setRegex(String regex) {
      this.regex = regex;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         SessionInputConstraint that = (SessionInputConstraint)o;
         return this.name.equals(that.name);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
