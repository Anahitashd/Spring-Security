package ir.fidar.pam.session.event;

import ir.fidar.pam.domain.model.session.SessionTransferredFile;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.SessionManager;
import java.time.Instant;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Service;

@Service
public class SessionFileTransferringEventListener implements ApplicationListener<SessionFileTransferringEvent> {
   private final CaptureService captureService;

   public SessionFileTransferringEventListener(CaptureService captureService) {
      this.captureService = captureService;
   }

   public void onApplicationEvent(SessionFileTransferringEvent sessionFileTransferringEvent) {
      SessionTransferredFile sessionTransferredFile = new SessionTransferredFile();
      sessionTransferredFile.setName(sessionFileTransferringEvent.getFileName());
      sessionTransferredFile.setMode(sessionFileTransferringEvent.getMode());
      sessionTransferredFile.setStatus(sessionFileTransferringEvent.getStatus());
      sessionTransferredFile.setTime((long)Long.valueOf(Instant.now().getEpochSecond()).intValue());
      this.captureService
         .updateSessionTransferredFiles(sessionTransferredFile, (ManagedSession)SessionManager.getSession(sessionFileTransferringEvent.getSessionId()));
   }
}
