package ir.fidar.pam.domain.dto.sessioninputconstraint;

import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;

public class SessionInputConstraintDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private String name;
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
