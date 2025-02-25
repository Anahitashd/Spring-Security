package ir.fidar.pam.domain.util.constraint;

import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import java.util.List;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class AccessibilityTimePeriodConstraintValidInfoValidator implements ConstraintValidator<AccessibilityTimePeriodConstraintValidInfo, AccessibilityTimePeriodConstraintCreateDto> {
   public boolean isValid(AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraintCreateDto, ConstraintValidatorContext constraintValidatorContext) {
      DailyAccessibilityTimePeriodConstraintDto dailyAccessibilityTimePeriodConstraintDto;
      List<WeeklyAccessibilityTimePeriodConstraintDto> weeklyConstraints;
      List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyConstraints;
      if (accessibilityTimePeriodConstraintCreateDto == null || accessibilityTimePeriodConstraintCreateDto.getMode() == null)
         return true;
      switch (accessibilityTimePeriodConstraintCreateDto.getMode()) {
         case DAILY:
            dailyAccessibilityTimePeriodConstraintDto = accessibilityTimePeriodConstraintCreateDto.getDailyConstraint();
            return validate(dailyAccessibilityTimePeriodConstraintDto.getFromHour().intValue(),
                    dailyAccessibilityTimePeriodConstraintDto.getFromMinute().intValue(),
                    dailyAccessibilityTimePeriodConstraintDto.getToHour().intValue(),
                    dailyAccessibilityTimePeriodConstraintDto.getToMinute().intValue());
         case WEEKLY:
            weeklyConstraints = accessibilityTimePeriodConstraintCreateDto.getWeeklyConstraints();
            for (WeeklyAccessibilityTimePeriodConstraintDto weeklyAccessibilityTimePeriodConstraintDto : weeklyConstraints) {
               if (!validate(weeklyAccessibilityTimePeriodConstraintDto.getFromHour().intValue(),
                       weeklyAccessibilityTimePeriodConstraintDto.getFromMinute().intValue(),
                       weeklyAccessibilityTimePeriodConstraintDto.getToHour().intValue(),
                       weeklyAccessibilityTimePeriodConstraintDto.getToMinute().intValue()))
                  return false;
            }
            return true;

         case MONTHLY:
            monthlyConstraints = accessibilityTimePeriodConstraintCreateDto.getMonthlyConstraints();
            for (MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto : monthlyConstraints) {
               if (!validate(monthlyAccessibilityTimePeriodConstraintDto.getFromHour().intValue(),
                       monthlyAccessibilityTimePeriodConstraintDto.getFromMinute().intValue(),
                       monthlyAccessibilityTimePeriodConstraintDto.getToHour().intValue(),
                       monthlyAccessibilityTimePeriodConstraintDto.getToMinute().intValue()))
                  return false;
            }
            return true;
      }
      return false;
   }

   private boolean validate(int fromHour, int fromMinute, int toHour, int toMinute) {
      if (fromHour < toHour)
         return true;
      if (fromHour > toHour)
         return false;
      if (fromMinute < toMinute)
         return true;
      if (fromMinute > toMinute)
         return false;
      return false;
   }
}
