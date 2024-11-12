package ir.fidar.pam.session.inputextraction.service.tasks;

import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RemoteSessionExtractionFinalizeTask extends SynchronizedTask {
   private static final Logger LOGGER = LogManager.getLogger();

   public RemoteSessionExtractionFinalizeTask(RemoteSessionInputExtraction remoteSessionInputExtraction) {
      super(remoteSessionInputExtraction);
   }

   @Override
   public void run() {
      this.getBoundedRemoteSessionInputExtraction().finish();
      LOGGER.debug(
         Markers.SESSION,
         "Remote session '{}' input extraction processing is finished and removed from extraction manager",
         this.getBoundedRemoteSessionInputExtraction().getManagedSession().getId()
      );
   }
}
