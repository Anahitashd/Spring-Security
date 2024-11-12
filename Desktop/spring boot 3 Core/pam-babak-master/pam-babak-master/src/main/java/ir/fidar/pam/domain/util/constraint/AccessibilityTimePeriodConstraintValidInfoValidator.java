package ir.fidar.pam.domain.util.constraint;

import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraintDto;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class AccessibilityTimePeriodConstraintValidInfoValidator
   implements ConstraintValidator<AccessibilityTimePeriodConstraintValidInfo, AccessibilityTimePeriodConstraintCreateDto> {
   public boolean isValid(
      AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraintCreateDto, ConstraintValidatorContext constraintValidatorContext
   ) {
      if (accessibilityTimePeriodConstraintCreateDto != null && accessibilityTimePeriodConstraintCreateDto.getMode() != null) {
         switch (accessibilityTimePeriodConstraintCreateDto.getMode()) {
            case DAILY:
               DailyAccessibilityTimePeriodConstraintDto dailyAccessibilityTimePeriodConstraintDto = accessibilityTimePeriodConstraintCreateDto.getDailyConstraint(
                  
               );
               return this.validate(
                  dailyAccessibilityTimePeriodConstraintDto.getFromHour(),
                  dailyAccessibilityTimePeriodConstraintDto.getFromMinute(),
                  dailyAccessibilityTimePeriodConstraintDto.getToHour(),
                  dailyAccessibilityTimePeriodConstraintDto.getToMinute()
               );
            case WEEKLY:
               for (WeeklyAccessibilityTimePeriodConstraintDto weeklyAccessibilityTimePeriodConstraintDto : accessibilityTimePeriodConstraintCreateDto.getWeeklyConstraints(
                  
               )) {
                  if (!this.validate(
                     weeklyAccessibilityTimePeriodConstraintDto.getFromHour(),
                     weeklyAccessibilityTimePeriodConstraintDto.getFromMinute(),
                     weeklyAccessibilityTimePeriodConstraintDto.getToHour(),
                     weeklyAccessibilityTimePeriodConstraintDto.getToMinute()
                  )) {
                     return false;
                  }
               }

               return true;
            case MONTHLY:
               for (MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto : accessibilityTimePeriodConstraintCreateDto.getMonthlyConstraints(
                  
               )) {
                  if (!this.validate(
                     monthlyAccessibilityTimePeriodConstraintDto.getFromHour(),
                     monthlyAccessibilityTimePeriodConstraintDto.getFromMinute(),
                     monthlyAccessibilityTimePeriodConstraintDto.getToHour(),
                     monthlyAccessibilityTimePeriodConstraintDto.getToMinute()
                  )) {
                     return false;
                  }
               }

               return true;
            default:
               return false;
         }
      } else {
         return true;
      }
   }

   private boolean validate(int fromHour, int fromMinute, int toHour, int toMinute) {
      if (fromHour < toHour) {
         return true;
      } else if (fromHour > toHour) {
         return false;
      } else if (fromMinute < toMinute) {
         return true;
      } else {
         return fromMinute > toMinute ? false : false;
      }
   }
}
