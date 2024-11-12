package ir.fidar.pam.domain.dto;

import ir.fidar.core.security.validation.XssProtected;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class BannerCreateDto {
   @NotBlank(
      message = "blank.message"
   )
   @Size(
      max = 255,
      message = "gt_max.message"
   )
   @XssProtected
   private String message;
   private boolean skippable;

   public String getMessage() {
      return this.message;
   }

   public void setMessage(String message) {
      this.message = message;
   }

   public boolean isSkippable() {
      return this.skippable;
   }

   public void setSkippable(boolean skippable) {
      this.skippable = skippable;
   }
}
