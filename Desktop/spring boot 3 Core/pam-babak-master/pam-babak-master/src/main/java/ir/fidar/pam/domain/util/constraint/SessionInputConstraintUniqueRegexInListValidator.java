package ir.fidar.pam.domain.util.constraint;

import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import java.util.List;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class SessionInputConstraintUniqueRegexInListValidator
   implements ConstraintValidator<SessionInputConstraintUniqueRegexInList, List<SessionInputConstraintViolationHandlerCreateDto>> {
   public boolean isValid(
      List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraintViolationHandlerCreateDtoList,
      ConstraintValidatorContext constraintValidatorContext
   ) {
      if (sessionInputConstraintViolationHandlerCreateDtoList != null
         && !sessionInputConstraintViolationHandlerCreateDtoList.isEmpty()
         && sessionInputConstraintViolationHandlerCreateDtoList.size() != 1) {
         SessionInputConstraintViolationHandlerCreateDto previousRecord = sessionInputConstraintViolationHandlerCreateDtoList.get(0);

         for (int i = 1; i < sessionInputConstraintViolationHandlerCreateDtoList.size(); i++) {
            SessionInputConstraintViolationHandlerCreateDto currentRecord = sessionInputConstraintViolationHandlerCreateDtoList.get(i);
            if (previousRecord.getConstraintRegex().equals(currentRecord.getConstraintRegex())) {
               return false;
            }
         }

         return true;
      } else {
         return true;
      }
   }
}
