package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.domain.util.constraint.Uuid;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;

@Entity
@Table(
   name = "tb_session_scanning_transferred_file"
)
public class SessionScanningTransferredFile extends BaseEntity {
   @NotBlank(
      message = "blank.uuid"
   )
   private String uuid;
   @NotBlank(
      message = "blank.fileName"
   )
   private String fileName;
   @Uuid
   private String kavoshRequestIdentifier;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "capture_id"
   )
   private Capture capture;
   @Min(
      value = 1L,
      message = "lt_min.registrationTime"
   )
   private long registrationTime;

   public String getUuid() {
      return this.uuid;
   }

   public void setUuid(String uuid) {
      this.uuid = uuid;
   }

   public String getFileName() {
      return this.fileName;
   }

   public void setFileName(String fileName) {
      this.fileName = fileName;
   }

   public String getKavoshRequestIdentifier() {
      return this.kavoshRequestIdentifier;
   }

   public void setKavoshRequestIdentifier(String kavoshRequestIdentifier) {
      this.kavoshRequestIdentifier = kavoshRequestIdentifier;
   }

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }

   public long getRegistrationTime() {
      return this.registrationTime;
   }

   public void setRegistrationTime(long registrationTime) {
      this.registrationTime = registrationTime;
   }
}
