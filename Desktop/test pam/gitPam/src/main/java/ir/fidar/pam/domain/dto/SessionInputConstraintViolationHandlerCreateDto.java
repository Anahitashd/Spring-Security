package ir.fidar.pam.domain.dto;

import ir.fidar.pam.domain.util.constraint.SessionInputConstraintAlertHandlerContactInfoProvided;
import ir.fidar.pam.domain.util.constraint.SessionInputConstraintHandlerTypeProvided;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@SessionInputConstraintHandlerTypeProvided(
   message = "no_handler_provided.input_const",
   targetClass = SessionInputConstraintViolationHandlerCreateDto.class
)
@SessionInputConstraintAlertHandlerContactInfoProvided(
   message = "no_contact_info.alert_handler",
   handlerFlagProperty = "alertSomeone",
   phoneNumberProperty = "phoneNumber",
   emailProperty = "email",
   targetClass = SessionInputConstraintViolationHandlerCreateDto.class
)
public class SessionInputConstraintViolationHandlerCreateDto {
   @NotBlank(
      message = "blank.constraintRegex"
   )
   private String constraintRegex;
   private boolean terminateSession;
   private boolean alertSomeone;
   private boolean preventExecution;
   private boolean sendNotification;
   @Email(
      message = "wrng_pattern.email"
   )
   @Size(
      max = 254,
      message = "gt_max.email"
   )
   private String email;
   @Pattern(
      regexp = "^\\+?\\d+$",
      message = "wrng_pattern.phoneNumber"
   )
   @Size(
      max = 32,
      message = "gt_max.phoneNumber"
   )
   private String phoneNumber;

   public String getConstraintRegex() {
      return this.constraintRegex;
   }

   public void setConstraintRegex(String constraintRegex) {
      this.constraintRegex = constraintRegex;
   }

   public boolean isTerminateSession() {
      return this.terminateSession;
   }

   public void setTerminateSession(boolean terminateSession) {
      this.terminateSession = terminateSession;
   }

   public boolean isAlertSomeone() {
      return this.alertSomeone;
   }

   public void setAlertSomeone(boolean alertSomeone) {
      this.alertSomeone = alertSomeone;
   }

   public boolean isPreventExecution() {
      return this.preventExecution;
   }

   public void setPreventExecution(boolean preventExecution) {
      this.preventExecution = preventExecution;
   }

   public boolean isSendNotification() {
      return this.sendNotification;
   }

   public void setSendNotification(boolean sendNotification) {
      this.sendNotification = sendNotification;
   }

   public String getEmail() {
      return this.email;
   }

   public void setEmail(String email) {
      this.email = email;
   }

   public String getPhoneNumber() {
      return this.phoneNumber;
   }

   public void setPhoneNumber(String phoneNumber) {
      this.phoneNumber = phoneNumber;
   }
}
