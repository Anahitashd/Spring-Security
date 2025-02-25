package ir.fidar.pam.service;

import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.model.session.SessionTransferredFile;
import ir.fidar.pam.session.ManagedSession;
import java.util.Set;

public interface CaptureService {
   Capture getBySessionId(String var1);

   void create(ManagedSession var1);

   void addNewSessionInputConstraintViolationIncident(SessionInputConstraintViolationIncident var1, ManagedSession var2);

   void updateSessionTransferredFiles(SessionTransferredFile var1, ManagedSession var2);

   void close(ManagedSession var1);

   boolean isSessionIdAlreadyRegistered(String var1);

   void syncCaptureAndSessionStatus(Set<String> var1);

   void saveCapture(Capture var1);

   boolean existAnyCapturedVideoForConnection(String var1);

   void addTransferredClipboard(String var1, CaptureTransferredClipboard var2);

   void addExecutedCommand(String var1, CaptureExecutedCommand var2);
}
