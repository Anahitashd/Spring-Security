package ir.fidar.pam.domain.dto;

import ir.fidar.core.domain.dto.crud.MutationOnlyReadDto;

public class SessionInputConstraintViolationHandlerDetailsDto extends MutationOnlyReadDto {
   private String constraintRegex;
   private boolean terminateSession;
   private boolean alertSomeone;
   private boolean preventExecution;
   private boolean sendNotification;
   private String email;
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
