package ir.fidar.pam.domain.util.constraint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Constraint(
   validatedBy = {SessionInputConstraintUniqueRegexInListValidator.class}
)
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface SessionInputConstraintUniqueRegexInList {
   String message() default "";

   Class<?>[] groups() default {};

   Class<? extends Payload>[] payload() default {};
}
