package ir.fidar.pam.domain.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class SymmetricKeyRegisterDto {
   @NotBlank(
      message = "blank.key"
   )
   @Size(
      max = 255,
      message = "gt_max.key"
   )
   private String key;

   public String getKey() {
      return this.key;
   }

   public void setKey(String key) {
      this.key = key;
   }
}
