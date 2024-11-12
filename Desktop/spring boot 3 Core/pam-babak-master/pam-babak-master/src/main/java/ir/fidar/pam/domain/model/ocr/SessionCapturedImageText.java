package ir.fidar.pam.domain.model.ocr;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.validation.XssProtected;
import jakarta.persistence.Entity;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Entity
@Table(
   name = "tb_session_captured_image_text"
)
public class SessionCapturedImageText extends BaseEntity {
   @NotBlank
   @XssProtected
   private String sessionId;
   @NotBlank
   private String imageFileName;
   @NotNull
   @Lob
   private byte[] content;

   public String getSessionId() {
      return this.sessionId;
   }

   public void setSessionId(String sessionId) {
      this.sessionId = sessionId;
   }

   public String getImageFileName() {
      return this.imageFileName;
   }

   public void setImageFileName(String imageFileName) {
      this.imageFileName = imageFileName;
   }

   public byte[] getContent() {
      return this.content;
   }

   public void setContent(byte[] content) {
      this.content = content;
   }
}
