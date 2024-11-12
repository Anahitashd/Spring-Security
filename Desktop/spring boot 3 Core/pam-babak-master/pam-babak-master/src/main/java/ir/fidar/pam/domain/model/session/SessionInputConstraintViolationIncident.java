package ir.fidar.pam.domain.model.session;

import ir.fidar.core.domain.model.BaseEntity;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

@Entity
@Table(
   name = "tb_session_input_constraint_violation_incident"
)
public class SessionInputConstraintViolationIncident extends BaseEntity {
   @NotBlank(
      message = "blank.regex"
   )
   private String regex;
   @NotBlank(
      message = "blank.input"
   )
   private String input;
   @Min(
      value = 0L,
      message = "lt_min.time"
   )
   @Max(
      value = 4000000000L,
      message = "gt_max.time"
   )
   private long time;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "capture_id"
   )
   private Capture capture;

   public String getRegex() {
      return this.regex;
   }

   public void setRegex(String regex) {
      this.regex = regex;
   }

   public String getInput() {
      return this.input;
   }

   public void setInput(String input) {
      this.input = input;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public Capture getCapture() {
      return this.capture;
   }

   public void setCapture(Capture capture) {
      this.capture = capture;
   }
}
