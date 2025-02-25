package ir.fidar.pam.domain.dto.capture;

public class CaptureClientInformationDetailsDto {
   private short screenWidth;
   private short screenHeight;
   private short screenDpi;

   public short getScreenWidth() {
      return this.screenWidth;
   }

   public void setScreenWidth(short screenWidth) {
      this.screenWidth = screenWidth;
   }

   public short getScreenHeight() {
      return this.screenHeight;
   }

   public void setScreenHeight(short screenHeight) {
      this.screenHeight = screenHeight;
   }

   public short getScreenDpi() {
      return this.screenDpi;
   }

   public void setScreenDpi(short screenDpi) {
      this.screenDpi = screenDpi;
   }
}
