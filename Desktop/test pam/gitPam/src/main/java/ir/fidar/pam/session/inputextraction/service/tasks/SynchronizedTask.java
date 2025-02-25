package ir.fidar.pam.session.inputextraction.service.tasks;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import java.time.Instant;

public abstract class SynchronizedTask implements Runnable {
   private final RemoteSessionInputExtraction remoteSessionInputExtraction;
   private final long registrationTime;

   protected SynchronizedTask(RemoteSessionInputExtraction remoteSessionInputExtraction) {
      this.remoteSessionInputExtraction = remoteSessionInputExtraction;
      this.registrationTime = Instant.now().getEpochSecond();
   }

   public long getRegistrationTime() {
      return this.registrationTime;
   }

   public RemoteSessionInputExtraction getBoundedRemoteSessionInputExtraction() {
      return this.remoteSessionInputExtraction;
   }
}
