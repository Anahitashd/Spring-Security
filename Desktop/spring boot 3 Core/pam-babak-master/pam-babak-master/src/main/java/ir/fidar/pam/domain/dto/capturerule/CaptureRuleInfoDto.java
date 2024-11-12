package ir.fidar.pam.domain.dto.capturerule;

import ir.fidar.core.domain.dto.crud.InfoDto;

public class CaptureRuleInfoDto implements InfoDto {
   private String name;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }
}
