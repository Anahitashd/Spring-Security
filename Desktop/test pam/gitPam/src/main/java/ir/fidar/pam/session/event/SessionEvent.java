package ir.fidar.pam.session.event;

import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.session.ManagedSession;
import org.springframework.context.ApplicationEvent;

public class SessionEvent extends ApplicationEvent {
   private final SessionEvent.EventType eventType;
   private final ManagedSession managedSession;
   private final SessionInputConstraintViolationIncident sessionInputConstraintViolationIncident;

   public SessionEvent(Object source, SessionEvent.EventType eventType, ManagedSession managedSession) {
      this(source, eventType, managedSession, null);
   }

   public SessionEvent(
      Object source,
      SessionEvent.EventType eventType,
      ManagedSession managedSession,
      SessionInputConstraintViolationIncident sessionInputConstraintViolationIncident
   ) {
      super(source);
      this.eventType = eventType;
      this.managedSession = managedSession;
      this.sessionInputConstraintViolationIncident = sessionInputConstraintViolationIncident;
   }

   public SessionEvent.EventType getEventType() {
      return this.eventType;
   }

   public ManagedSession getManagedSession() {
      return this.managedSession;
   }

   public SessionInputConstraintViolationIncident getSessionInputConstraintViolationIncident() {
      return this.sessionInputConstraintViolationIncident;
   }

   public static enum EventType {
      START,
      CLOSE,
      UPDATE_INCIDENT;
   }
}
