package ir.fidar.pam.domain.model;

import ir.fidar.core.domain.model.MutationOnlyBaseEntity;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.util.constraint.SessionInputConstraintAlertHandlerContactInfoProvided;
import ir.fidar.pam.domain.util.constraint.SessionInputConstraintHandlerTypeProvided;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.validation.constraints.Email;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_session_input_constraint_violation_handler"
)
@SessionInputConstraintHandlerTypeProvided(
   message = "no_handler_provided.input_const",
   targetClass = SessionInputConstraintViolationHandler.class
)
@SessionInputConstraintAlertHandlerContactInfoProvided(
   message = "no_contact_info.alert_handler",
   handlerFlagProperty = "alertSomeone",
   phoneNumberProperty = "phoneNumber",
   emailProperty = "email",
   targetClass = SessionInputConstraintViolationHandler.class
)
public class SessionInputConstraintViolationHandler extends MutationOnlyBaseEntity {
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "constraint_id"
   )
   private SessionInputConstraint inputConstraint;
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
   @XssProtected
   private String phoneNumber;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "access_rule_id"
   )
   private AccessRule accessRule;
   @ManyToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "connection_id"
   )
   private Connection connection;

   public SessionInputConstraint getInputConstraint() {
      return this.inputConstraint;
   }

   public void setInputConstraint(SessionInputConstraint inputConstraint) {
      this.inputConstraint = inputConstraint;
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

   public AccessRule getAccessRule() {
      return this.accessRule;
   }

   public void setAccessRule(AccessRule accessRule) {
      this.accessRule = accessRule;
   }

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }
}
