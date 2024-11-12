package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.CaptureTransferredClipboardSource;
import ir.fidar.pam.domain.util.converter.attribbute.CaptureTransferredClipboardSourceConverter;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(
   name = "tb_capture_transferred_clipboard"
)
public class CaptureTransferredClipboard extends BaseEntity {
   @NotBlank(
      message = "blank.content"
   )
   @Size(
      max = 10000,
      message = "gt_max.content"
   )
   @XssProtected
   private String content;
   @Min(
      value = 1L,
      message = "lt_min.time"
   )
   @Max(
      value = 4000000000L,
      message = "gt_max.time"
   )
   private long time;
   @Min(
      value = 1L,
      message = "lt_min.elapsedTime"
   )
   private Integer elapsedTime;
   @NotNull(
      message = "null.source"
   )
   @Convert(
      converter = CaptureTransferredClipboardSourceConverter.class
   )
   private CaptureTransferredClipboardSource source;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "capture_id"
   )
   private Capture capture;

   public String getContent() {
      return this.content;
   }

   public void setContent(String content) {
      this.content = content;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public int getElapsedTime() {
      return this.elapsedTime;
   }

   public void setElapsedTime(int elapsedTime) {
      this.elapsedTime = elapsedTime;
   }

   public CaptureTransferredClipboardSource getSource() {
      return this.source;
   }

   public void setSource(CaptureTransferredClipboardSource source) {
      this.source = source;
   }

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }
}
