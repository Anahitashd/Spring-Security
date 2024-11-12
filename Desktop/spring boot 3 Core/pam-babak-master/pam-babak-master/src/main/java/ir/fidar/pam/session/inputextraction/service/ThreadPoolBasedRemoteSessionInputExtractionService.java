package ir.fidar.pam.session.inputextraction.service;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.RemoteSessionInputExtractionProperties;
import ir.fidar.pam.session.inputextraction.model.ReactiveRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionExtractionTaskRegistry;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtractionStatus;
import ir.fidar.pam.session.inputextraction.model.callback.InputExtractionTaskFinishCallback;
import ir.fidar.pam.session.inputextraction.model.callback.RemoteSessionExtractionStatusChangeCallback;
import ir.fidar.pam.session.inputextraction.model.consoletype.ReactiveConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.InstructionProcessingService;
import ir.fidar.pam.session.inputextraction.service.tasks.ExtractionTaskRegistrationTask;
import ir.fidar.pam.session.inputextraction.service.tasks.RemoteSessionExtractionFinalizeTask;
import ir.fidar.pam.session.inputextraction.service.tasks.RemoteSessionInputExtractionTask;
import ir.fidar.pam.session.inputextraction.writer.ClipboardInputWriter;
import ir.fidar.pam.session.inputextraction.writer.KeyInputWriter;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.stereotype.Service;

@Service
public class ThreadPoolBasedRemoteSessionInputExtractionService implements RemoteSessionInputExtractionService, DisposableBean {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final ConcurrentMap<String, RemoteSessionInputExtraction> REMOTE_SESSIONS = new ConcurrentHashMap<>();
   private final int maxPoolSize;
   private final String threadNamePrefix;
   private final InstructionProcessingService instructionProcessingService;
   private final ExecutorService extractionService;
   private final RemoteSessionExtractionStatusChangeCallback extractionStatusChangeCallback;
   private final InputExtractionTaskFinishCallback extractionTaskFinishCallback;
   private final CaptureService captureService;

   public ThreadPoolBasedRemoteSessionInputExtractionService(
      InstructionProcessingService instructionProcessingService,
      CaptureService captureService,
      RemoteSessionInputExtractionProperties remoteSessionInputExtractionProperties
   ) {
      this.maxPoolSize = remoteSessionInputExtractionProperties.getMaxPoolSize();
      this.threadNamePrefix = remoteSessionInputExtractionProperties.getThreadNamePrefix();
      this.instructionProcessingService = instructionProcessingService;
      this.captureService = captureService;
      this.extractionService = new AdjustableThreadPoolExecutorService(this.maxPoolSize, new NamePrefixAwareThreadFactory(this.threadNamePrefix));
      this.extractionStatusChangeCallback = new ThreadPoolBasedRemoteSessionInputExtractionService.SimpleExtractionStatusChangeCallback(this.extractionService);
      this.extractionTaskFinishCallback = new ThreadPoolBasedRemoteSessionInputExtractionService.SimpleExtractionTaskFinishCallback();
      LOGGER.debug(
         Markers.SESSION,
         "Remote session extraction service is initialized with maximum '{}' threads. Threads' name prefix: {}",
         this.maxPoolSize,
         this.threadNamePrefix
      );
   }

   public int getMaxPoolSize() {
      return this.maxPoolSize;
   }

   public String getThreadNamePrefix() {
      return this.threadNamePrefix;
   }

   @Override
   public ExecutorService getExtractionService() {
      return this.extractionService;
   }

   @Override
   public void registerNewSession(ManagedSession managedSession) throws IOException {
      String sessionId = managedSession.getId();
      if (!REMOTE_SESSIONS.containsKey(sessionId)) {
         KeyInputWriter keyWriter = new KeyInputWriter(this.resolveKeyStoragePath(managedSession));
         ClipboardInputWriter clipboardWriter = new ClipboardInputWriter(this.captureService, managedSession);
         if (this.isConsoleType(managedSession)) {
            REMOTE_SESSIONS.put(
               sessionId,
               new ReactiveConsoleTypeRemoteSessionInputExtraction(
                  managedSession,
                  keyWriter,
                  clipboardWriter,
                  new ReactiveConsoleTypeRemoteSessionInputExtraction.CommandInputWriter(this.captureService),
                  this.extractionStatusChangeCallback
               )
            );
         } else {
            REMOTE_SESSIONS.put(
               sessionId, new ReactiveRemoteSessionInputExtraction(managedSession, keyWriter, clipboardWriter, this.extractionStatusChangeCallback)
            );
         }

         LOGGER.debug(Markers.SESSION, "New remote session '{}' is registered for input extraction processing", managedSession.getId());
      }
   }

   @Override
   public void submitNewTask(RemoteSessionExtractionTaskRegistry extractionTaskRegistry) {
      RemoteSessionInputExtraction remoteSessionInputExtraction = this.retrieveBySessionId(extractionTaskRegistry.getSessionId());
      if (remoteSessionInputExtraction != null) {
         this.extractionService
            .execute(
               new ExtractionTaskRegistrationTask(
                  remoteSessionInputExtraction, extractionTaskRegistry, this.instructionProcessingService, this.extractionTaskFinishCallback
               )
            );
      }
   }

   @Override
   public void finalizeExtraction(String sessionId) {
      this.extractionService.submit(new RemoteSessionExtractionFinalizeTask(this.retrieveBySessionId(sessionId)));
   }

   public void destroy() throws Exception {
      if (!this.extractionService.isShutdown()) {
         this.extractionService.shutdown();
         this.extractionService.awaitTermination(5L, TimeUnit.MINUTES);
      }

      LOGGER.debug(Markers.SESSION, "Remote session input extraction executor service is shutdown gracefully");
   }

   private RemoteSessionInputExtraction retrieveBySessionId(String sessionId) {
      return REMOTE_SESSIONS.getOrDefault(sessionId, null);
   }

   private boolean isConsoleType(ManagedSession managedSession) {
      return managedSession.getConnection().getType().equals(ConnectionType.SSH) || managedSession.getConnection().getType().equals(ConnectionType.RDP);
   }

   private String resolveKeyStoragePath(ManagedSession managedSession) {
      return managedSession.getAccessRule().getBridge().getRecordsStoragePath()
         + "/"
         + managedSession.getAccessRule().getUuid()
         + "/"
         + managedSession.getId()
         + ".keys";
   }

   private static class SimpleExtractionStatusChangeCallback implements RemoteSessionExtractionStatusChangeCallback {
      private final ExecutorService taskExecutorService;

      private SimpleExtractionStatusChangeCallback(ExecutorService taskExecutorService) {
         this.taskExecutorService = taskExecutorService;
      }

      @Override
      public void onStatusChange(RemoteSessionInputExtraction remoteSessionInputExtraction) {
         switch (remoteSessionInputExtraction.getStatus()) {
            case READY_TO_PROCESS:
               RemoteSessionInputExtractionTask extractionTask = remoteSessionInputExtraction.getNextTask();
               if (extractionTask != null) {
                  remoteSessionInputExtraction.setStatus(RemoteSessionInputExtractionStatus.PROCESSING);
                  this.taskExecutorService.execute(extractionTask);
               }
               break;
            case FINISHED:
               ThreadPoolBasedRemoteSessionInputExtractionService.REMOTE_SESSIONS.remove(remoteSessionInputExtraction.getManagedSession().getId());
         }
      }
   }

   private static class SimpleExtractionTaskFinishCallback implements InputExtractionTaskFinishCallback {
      private SimpleExtractionTaskFinishCallback() {
      }

      @Override
      public void onFinish(RemoteSessionInputExtraction remoteSessionInputExtraction) {
         remoteSessionInputExtraction.setStatus(RemoteSessionInputExtractionStatus.READY_TO_PROCESS);
      }
   }
}
