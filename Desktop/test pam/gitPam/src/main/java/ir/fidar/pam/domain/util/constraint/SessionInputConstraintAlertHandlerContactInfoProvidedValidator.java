package ir.fidar.pam.domain.util.constraint;

import com.google.common.base.Predicate;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.exception.ConstraintInvalidUsageException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Set;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import org.reflections.ReflectionUtils;

public class SessionInputConstraintAlertHandlerContactInfoProvidedValidator
   implements ConstraintValidator<SessionInputConstraintAlertHandlerContactInfoProvided, Object> {
   private Method flagGetter;
   private Method emailGetter;
   private Method phoneNumberGetter;

   public void initialize(SessionInputConstraintAlertHandlerContactInfoProvided constraintAnnotation) {
      this.flagGetter = this.findGetter(constraintAnnotation.handlerFlagProperty(), "is", constraintAnnotation.targetClass());
      this.emailGetter = this.findGetter(constraintAnnotation.emailProperty(), "get", constraintAnnotation.targetClass());
      this.phoneNumberGetter = this.findGetter(constraintAnnotation.phoneNumberProperty(), "get", constraintAnnotation.targetClass());
   }

   public boolean isValid(Object object, ConstraintValidatorContext constraintValidatorContext) {
      try {
         boolean flagValue = (Boolean)this.flagGetter.invoke(object);
         String email = (String)this.emailGetter.invoke(object);
         String phoneNumber = (String)this.phoneNumberGetter.invoke(object);
         return !flagValue || StringUtils.hasContent(email) || StringUtils.hasContent(phoneNumber);
      } catch (InvocationTargetException | IllegalAccessException var6) {
         throw new SystemInternalErrorException(var6);
      }
   }

   private Method findGetter(String property, String getterPrefix, Class<?> targetClass) {
      String getterName = getterPrefix + Character.toUpperCase(property.charAt(0)) + property.substring(1);
      Set<Method> getters = ReflectionUtils.getAllMethods(targetClass, new Predicate[]{ReflectionUtils.withName(getterName)});
      if (!getters.isEmpty() && getters.size() <= 1) {
         return getters.iterator().next();
      } else {
         throw new SystemInternalErrorException(
            new ConstraintInvalidUsageException(
               String.format(
                  "invalid usage of %s: found %d getters for property %s. it must be 1",
                  SessionInputConstraintAlertHandlerContactInfoProvided.class.getSimpleName(),
                  getters.size(),
                  property
               )
            )
         );
      }
   }
}
