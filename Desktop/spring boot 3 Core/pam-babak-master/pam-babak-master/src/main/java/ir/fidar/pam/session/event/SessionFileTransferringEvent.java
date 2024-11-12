package ir.fidar.pam.session.event;

import ir.fidar.pam.domain.type.SessionTransferFileMode;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;
import org.springframework.context.ApplicationEvent;

public class SessionFileTransferringEvent extends ApplicationEvent {
   private final String sessionId;
   private final String fileName;
   private final SessionTransferFileMode mode;
   private final SessionTransferredFileStatus status;

   public SessionFileTransferringEvent(Object source, String sessionId, String fileName, SessionTransferFileMode mode, SessionTransferredFileStatus status) {
      super(source);
      this.sessionId = sessionId;
      this.fileName = fileName;
      this.mode = mode;
      this.status = status;
   }

   public String getSessionId() {
      return this.sessionId;
   }

   public String getFileName() {
      return this.fileName;
   }

   public SessionTransferFileMode getMode() {
      return this.mode;
   }

   public SessionTransferredFileStatus getStatus() {
      return this.status;
   }
}
