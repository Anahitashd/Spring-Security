package ir.fidar.pam.domain.util.constraint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import javax.validation.Constraint;
import javax.validation.Payload;

@Constraint(
   validatedBy = {AccessibilityTimePeriodConstraintValidInfoValidator.class}
)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
public @interface AccessibilityTimePeriodConstraintValidInfo {
   String message() default "";

   Class<?>[] groups() default {};

   Class<? extends Payload>[] payload() default {};
}
