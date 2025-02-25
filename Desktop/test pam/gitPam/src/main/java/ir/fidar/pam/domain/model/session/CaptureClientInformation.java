package ir.fidar.pam.domain.model.session;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;

@Entity
@Table(
   name = "tb_capture_client_information"
)
public class CaptureClientInformation {
   @Id
   private Long id;
   private short screenWidth;
   private short screenHeight;
   private short screenDpi;
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "id"
   )
   @MapsId
   private Capture capture;

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

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }
}
