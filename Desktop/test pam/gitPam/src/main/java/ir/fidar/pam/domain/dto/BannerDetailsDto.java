package ir.fidar.pam.domain.dto;

public class BannerDetailsDto {
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
