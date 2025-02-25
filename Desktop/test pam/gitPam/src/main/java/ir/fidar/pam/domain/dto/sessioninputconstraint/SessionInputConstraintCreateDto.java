package ir.fidar.pam.domain.dto.sessioninputconstraint;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class SessionInputConstraintCreateDto extends AbstractDescriptiveCreateDto {
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
}
