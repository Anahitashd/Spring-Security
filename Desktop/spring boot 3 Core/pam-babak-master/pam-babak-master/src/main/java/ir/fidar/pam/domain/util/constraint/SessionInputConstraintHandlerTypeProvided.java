package ir.fidar.pam.domain.util.constraint;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Constraint(
   validatedBy = {SessionInputConstraintHandlerTypeProvidedValidator.class}
)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface SessionInputConstraintHandlerTypeProvided {
   String message() default "";

   String terminateSessionProperty() default "terminateSession";

   String alertSomeoneProperty() default "alertSomeone";

   String sendNotificationProperty() default "sendNotification";

   String preventExecutionProperty() default "preventExecution";

   Class<?> targetClass();

   Class<?>[] groups() default {};

   Class<? extends Payload>[] payload() default {};
}
