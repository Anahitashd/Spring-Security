package ir.fidar.pam.domain.util.constraint;

import com.google.common.base.Predicate;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.pam.exception.ConstraintInvalidUsageException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import org.reflections.ReflectionUtils;

public class SessionInputConstraintHandlerTypeProvidedValidator implements ConstraintValidator<SessionInputConstraintHandlerTypeProvided, Object> {
   private Method terminateSessionFlagGetter;
   private Method alertSomeoneFlagGetter;
   private Method preventExecutionFlagGetter;
   private Method sendNotificationFlagGetter;

   public void initialize(SessionInputConstraintHandlerTypeProvided constraintAnnotation) {
      this.terminateSessionFlagGetter = this.findGetter(constraintAnnotation.terminateSessionProperty(), constraintAnnotation.targetClass());
      this.alertSomeoneFlagGetter = this.findGetter(constraintAnnotation.alertSomeoneProperty(), constraintAnnotation.targetClass());
      this.preventExecutionFlagGetter = this.findGetter(constraintAnnotation.preventExecutionProperty(), constraintAnnotation.targetClass());
      this.sendNotificationFlagGetter = this.findGetter(constraintAnnotation.sendNotificationProperty(), constraintAnnotation.targetClass());
   }

   public boolean isValid(Object object, ConstraintValidatorContext constraintValidatorContext) {
      try {
         boolean terminateSession = (Boolean)this.terminateSessionFlagGetter.invoke(object);
         boolean alertSomeone = (Boolean)this.alertSomeoneFlagGetter.invoke(object);
         boolean preventExecution = (Boolean)this.preventExecutionFlagGetter.invoke(object);
         boolean sendNotification = (Boolean)this.sendNotificationFlagGetter.invoke(object);
         return terminateSession || alertSomeone || preventExecution || sendNotification;
      } catch (InvocationTargetException | IllegalAccessException var7) {
         throw new SystemInternalErrorException(var7);
      }
   }

   private Method findGetter(String property, Class<?> targetClass) {
      String getterName = "is" + Character.toUpperCase(property.charAt(0)) + property.substring(1);
      Set<Method> getters = ReflectionUtils.getAllMethods(targetClass, new Predicate[]{ReflectionUtils.withName(getterName)});
      if (!getters.isEmpty() && getters.size() <= 1) {
         return getters.iterator().next();
      } else {
         throw new SystemInternalErrorException(
            new ConstraintInvalidUsageException(
               String.format(
                  "invalid usage of %s: found %d getters for property %s. it must be 1",
                  SessionInputConstraintHandlerTypeProvided.class.getSimpleName(),
                  getters.size(),
                  property
               )
            )
         );
      }
   }
}
