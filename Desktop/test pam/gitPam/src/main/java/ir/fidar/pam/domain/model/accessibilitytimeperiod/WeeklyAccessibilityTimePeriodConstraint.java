package ir.fidar.pam.domain.model.accessibilitytimeperiod;

import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.pam.domain.type.WeekDay;
import ir.fidar.pam.domain.util.converter.attribbute.WeekDayConverter;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

@Entity
@Table(
   name = "tb_weekly_accessibility_time_period_constraint"
)
public class WeeklyAccessibilityTimePeriodConstraint extends BaseEntity {
   @NotNull(
      message = "null.weekDay"
   )
   @Convert(
      converter = WeekDayConverter.class
   )
   private WeekDay weekDay;
   @NotNull(
      message = "null.fromHour"
   )
   @Min(
      value = 0L,
      message = "lt_min.fromHour"
   )
   @Max(
      value = 23L,
      message = "gt_max.fromHour"
   )
   private Integer fromHour;
   @NotNull(
      message = "null.fromMinute"
   )
   @Min(
      value = 0L,
      message = "lt_min.fromMinute"
   )
   @Max(
      value = 59L,
      message = "gt_max.fromMinute"
   )
   private Integer fromMinute;
   @NotNull(
      message = "null.toHour"
   )
   @Min(
      value = 0L,
      message = "lt_min.toHour"
   )
   @Max(
      value = 23L,
      message = "gt_max.toHour"
   )
   private Integer toHour;
   @NotNull(
      message = "null.toMinute"
   )
   @Min(
      value = 0L,
      message = "lt_min.toMinute"
   )
   @Max(
      value = 59L,
      message = "gt_max.toMinute"
   )
   private Integer toMinute;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "time_period_id"
   )
   private AccessibilityTimePeriodConstraint timePeriodConstraint;

   public WeekDay getWeekDay() {
      return this.weekDay;
   }

   public void setWeekDay(WeekDay weekDay) {
      this.weekDay = weekDay;
   }

   public Integer getFromHour() {
      return this.fromHour;
   }

   public void setFromHour(Integer fromHour) {
      this.fromHour = fromHour;
   }

   public Integer getFromMinute() {
      return this.fromMinute;
   }

   public void setFromMinute(Integer fromMinute) {
      this.fromMinute = fromMinute;
   }

   public Integer getToHour() {
      return this.toHour;
   }

   public void setToHour(Integer toHour) {
      this.toHour = toHour;
   }

   public Integer getToMinute() {
      return this.toMinute;
   }

   public void setToMinute(Integer toMinute) {
      this.toMinute = toMinute;
   }

   public AccessibilityTimePeriodConstraint getTimePeriodConstraint() {
      return this.timePeriodConstraint;
   }

   public void setTimePeriodConstraint(AccessibilityTimePeriodConstraint timePeriodConstraint) {
      this.timePeriodConstraint = timePeriodConstraint;
   }
}
