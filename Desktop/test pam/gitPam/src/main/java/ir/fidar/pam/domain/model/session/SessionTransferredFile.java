package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.pam.domain.type.SessionTransferFileMode;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;
import ir.fidar.pam.domain.util.converter.attribbute.SessionTransferredFileModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.SessionTransferredFileStatusConverter;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Entity
@Table(
   name = "tb_session_transferred_file"
)
public class SessionTransferredFile extends BaseEntity {
   @NotBlank(
      message = "blank.name"
   )
   private String name;
   @Min(
      value = 1L,
      message = "lt_min.time"
   )
   @Max(
      value = 4000000000L,
      message = "gt_max.time"
   )
   private long time;
   @NotNull(
      message = "null.mode"
   )
   @Convert(
      converter = SessionTransferredFileModeConverter.class
   )
   private SessionTransferFileMode mode;
   @NotNull(
      message = "null.status"
   )
   @Convert(
      converter = SessionTransferredFileStatusConverter.class
   )
   private SessionTransferredFileStatus status;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "capture_id"
   )
   private Capture capture;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public SessionTransferFileMode getMode() {
      return this.mode;
   }

   public void setMode(SessionTransferFileMode mode) {
      this.mode = mode;
   }

   public SessionTransferredFileStatus getStatus() {
      return this.status;
   }

   public void setStatus(SessionTransferredFileStatus status) {
      this.status = status;
   }

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }
}
