package ir.fidar.pam.session.inputextraction.service;

import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionExtractionTaskRegistry;
import java.io.IOException;
import java.util.concurrent.ExecutorService;

public interface RemoteSessionInputExtractionService {
   ExecutorService getExtractionService();

   void registerNewSession(ManagedSession var1) throws IOException;

   void submitNewTask(RemoteSessionExtractionTaskRegistry var1);

   void finalizeExtraction(String var1);
}
