package ir.fidar.pam.domain.model.ocr;

import ir.fidar.core.domain.model.BaseEntity;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

@Entity
@Table(
   name = "tb_session_captured_image"
)
public class SessionCapturedImage extends BaseEntity {
   @NotBlank
   private String sessionId;
   @NotBlank
   private String imageData;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String sessionId) {
      this.sessionId = sessionId;
   }

   public String getImageData() {
      return this.imageData;
   }

   public void setImageData(String imageData) {
      this.imageData = imageData;
   }
}
