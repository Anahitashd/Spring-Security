package ir.fidar.pam.domain.dto.accessibilitytimeperiod;

import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import ir.fidar.pam.domain.util.constraint.AccessibilityConstraintModeInfoProvided;
import ir.fidar.pam.domain.util.constraint.AccessibilityTimePeriodConstraintValidInfo;
import java.util.List;
import jakarta.validation.constraints.NotNull;

@AccessibilityConstraintModeInfoProvided(
   message = "accessibility_time_period_const.no_info_provided"
)
@AccessibilityTimePeriodConstraintValidInfo(
   message = "accessibility_time_period_const.invalid_info"
)
public class AccessibilityTimePeriodConstraintCreateDto {
   @NotNull(
      message = "null.mode"
   )
   private AccessibilityTimePeriodMode mode;
   private DailyAccessibilityTimePeriodConstraintDto dailyConstraint;
   private List<WeeklyAccessibilityTimePeriodConstraintDto> weeklyConstraints;
   private List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyConstraints;

   public AccessibilityTimePeriodMode getMode() {
      return this.mode;
   }

   public void setMode(AccessibilityTimePeriodMode mode) {
      this.mode = mode;
   }

   public DailyAccessibilityTimePeriodConstraintDto getDailyConstraint() {
      return this.dailyConstraint;
   }

   public void setDailyConstraint(DailyAccessibilityTimePeriodConstraintDto dailyConstraint) {
      this.dailyConstraint = dailyConstraint;
   }

   public List<WeeklyAccessibilityTimePeriodConstraintDto> getWeeklyConstraints() {
      return this.weeklyConstraints;
   }

   public void setWeeklyConstraints(List<WeeklyAccessibilityTimePeriodConstraintDto> weeklyConstraints) {
      this.weeklyConstraints = weeklyConstraints;
   }

   public List<MonthlyAccessibilityTimePeriodConstraintDto> getMonthlyConstraints() {
      return this.monthlyConstraints;
   }

   public void setMonthlyConstraints(List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyConstraints) {
      this.monthlyConstraints = monthlyConstraints;
   }
}
