package ir.fidar.pam.domain.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

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
