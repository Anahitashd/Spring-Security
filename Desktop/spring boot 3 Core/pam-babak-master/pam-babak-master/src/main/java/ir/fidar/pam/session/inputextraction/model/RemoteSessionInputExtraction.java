package ir.fidar.pam.session.inputextraction.model;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.inputextraction.service.tasks.RemoteSessionInputExtractionTask;
import java.io.IOException;

public interface RemoteSessionInputExtraction {
   ManagedSession getManagedSession();

   RemoteSessionInputProcessingStatus getInputStatus();

   void setInputStatus(RemoteSessionInputProcessingStatus var1);

   RemoteSessionInputExtractionStatus getStatus();

   void setStatus(RemoteSessionInputExtractionStatus var1);

   FunctionalKeysState getFunctionalKeyState();

   void addNewTask(RemoteSessionInputExtractionTask var1);

   RemoteSessionInputExtractionTask getNextTask();

   RemoteSessionInputExtractionTask getCurrentProcessingTask();

   void setBaseTime();

   long getBaseTime();

   long getElapsedTime();

   void saveKey(KeyInfo var1) throws IOException;

   void saveClipboard(ClipboardInfo var1) throws IOException;

   void finish();

   default Connection getUnderlyingConnection() {
      return this.getManagedSession().getConnection();
   }
}
