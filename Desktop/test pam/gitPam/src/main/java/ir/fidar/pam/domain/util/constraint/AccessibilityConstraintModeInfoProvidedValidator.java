package ir.fidar.pam.domain.util.constraint;

import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraintDto;
import java.util.List;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class AccessibilityConstraintModeInfoProvidedValidator
   implements ConstraintValidator<AccessibilityConstraintModeInfoProvided, AccessibilityTimePeriodConstraintCreateDto> {
   public boolean isValid(
      AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraintCreateDto, ConstraintValidatorContext constraintValidatorContext
   ) {
      if (accessibilityTimePeriodConstraintCreateDto != null && accessibilityTimePeriodConstraintCreateDto.getMode() != null) {
         switch (accessibilityTimePeriodConstraintCreateDto.getMode()) {
            case DAILY:
               DailyAccessibilityTimePeriodConstraintDto dailyAccessibilityTimePeriodConstraintDto = accessibilityTimePeriodConstraintCreateDto.getDailyConstraint(
                  
               );
               return dailyAccessibilityTimePeriodConstraintDto != null
                  && dailyAccessibilityTimePeriodConstraintDto.getFromHour() != null
                  && dailyAccessibilityTimePeriodConstraintDto.getFromMinute() != null
                  && dailyAccessibilityTimePeriodConstraintDto.getToHour() != null
                  && dailyAccessibilityTimePeriodConstraintDto.getToMinute() != null;
            case WEEKLY:
               List<WeeklyAccessibilityTimePeriodConstraintDto> weeklyAccessibilityTimePeriodConstraintDtoList = accessibilityTimePeriodConstraintCreateDto.getWeeklyConstraints(
                  
               );
               if (weeklyAccessibilityTimePeriodConstraintDtoList != null && !weeklyAccessibilityTimePeriodConstraintDtoList.isEmpty()) {
                  for (WeeklyAccessibilityTimePeriodConstraintDto weeklyAccessibilityTimePeriodConstraintDto : weeklyAccessibilityTimePeriodConstraintDtoList) {
                     if (weeklyAccessibilityTimePeriodConstraintDto == null
                        || weeklyAccessibilityTimePeriodConstraintDto.getWeekDay() == null
                        || weeklyAccessibilityTimePeriodConstraintDto.getFromHour() == null
                        || weeklyAccessibilityTimePeriodConstraintDto.getFromMinute() == null
                        || weeklyAccessibilityTimePeriodConstraintDto.getToHour() == null
                        || weeklyAccessibilityTimePeriodConstraintDto.getToMinute() == null) {
                        return false;
                     }
                  }

                  return true;
               }
               break;
            case MONTHLY:
               List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyAccessibilityTimePeriodConstraintDtoList = accessibilityTimePeriodConstraintCreateDto.getMonthlyConstraints(
                  
               );
               if (monthlyAccessibilityTimePeriodConstraintDtoList != null && !monthlyAccessibilityTimePeriodConstraintDtoList.isEmpty()) {
                  for (MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto : monthlyAccessibilityTimePeriodConstraintDtoList) {
                     if (monthlyAccessibilityTimePeriodConstraintDto == null
                        || monthlyAccessibilityTimePeriodConstraintDto.getMonthDay() == null
                        || monthlyAccessibilityTimePeriodConstraintDto.getFromHour() == null
                        || monthlyAccessibilityTimePeriodConstraintDto.getFromMinute() == null
                        || monthlyAccessibilityTimePeriodConstraintDto.getToHour() == null
                        || monthlyAccessibilityTimePeriodConstraintDto.getToMinute() == null) {
                        return false;
                     }
                  }

                  return true;
               }
         }

         return false;
      } else {
         return true;
      }
   }
}
