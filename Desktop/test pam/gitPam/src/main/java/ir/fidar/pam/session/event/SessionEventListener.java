package ir.fidar.pam.session.event;

import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.CaptureService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

@Service
public class SessionEventListener implements ApplicationListener<SessionEvent> {
   private static final Logger LOGGER = LogManager.getLogger();
   private final CaptureService captureService;

   public SessionEventListener(CaptureService captureService) {
      this.captureService = captureService;
   }

   public void onApplicationEvent(SessionEvent sessionEvent) {
      LOGGER.debug(
         Markers.SESSION,
         "New session event is published for session '{}'. status: {}",
         sessionEvent.getManagedSession().getId(),
         sessionEvent.getManagedSession().getStatus()
      );
      switch (sessionEvent.getEventType()) {
         case START:
            this.captureService.create(sessionEvent.getManagedSession());
            break;
         case UPDATE_INCIDENT:
            this.captureService
               .addNewSessionInputConstraintViolationIncident(sessionEvent.getSessionInputConstraintViolationIncident(), sessionEvent.getManagedSession());
         case CLOSE:
            this.captureService.close(sessionEvent.getManagedSession());
      }
   }
}
