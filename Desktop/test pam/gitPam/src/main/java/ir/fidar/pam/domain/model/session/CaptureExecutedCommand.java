package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_capture_executed_command"
)
public class CaptureExecutedCommand extends BaseEntity {
   @NotBlank(
      message = "blank.content"
   )
   @Size(
      max = 2000,
      message = "gt_max"
   )
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

   public Integer getElapsedTime() {
      return this.elapsedTime;
   }

   public void setElapsedTime(Integer elapsedTime) {
      this.elapsedTime = elapsedTime;
   }

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }
}
