package ir.fidar.pam.session.inputextraction.model;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.inputextraction.model.callback.RemoteSessionExtractionStatusChangeCallback;
import ir.fidar.pam.session.inputextraction.service.tasks.RemoteSessionInputExtractionTask;
import ir.fidar.pam.session.inputextraction.writer.ExtractedInputWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReactiveRemoteSessionInputExtraction implements RemoteSessionInputExtraction {
   private static final Logger LOGGER = LogManager.getLogger();
   private final ManagedSession managedSession;
   private final FunctionalKeysState functionalKeysState;
   private final ConcurrentLinkedQueue<RemoteSessionInputExtractionTask> tasks;
   private final ExtractedInputWriter<KeyInfo> keyWriter;
   private final ExtractedInputWriter<ClipboardInfo> clipboardWriter;
   private final RemoteSessionExtractionStatusChangeCallback statusChangeCallback;
   private RemoteSessionInputProcessingStatus inputStatus;
   private RemoteSessionInputExtractionStatus status;
   private RemoteSessionInputExtractionConnectionStatus connectionStatus;
   private RemoteSessionInputExtractionTask currentProcessingTask;
   private long baseTime;

   public ReactiveRemoteSessionInputExtraction(
      ManagedSession managedSession,
      ExtractedInputWriter<KeyInfo> keyWriter,
      ExtractedInputWriter<ClipboardInfo> clipboardWriter,
      RemoteSessionExtractionStatusChangeCallback statusChangeCallback
   ) throws IOException {
      this.managedSession = managedSession;
      this.keyWriter = keyWriter;
      this.clipboardWriter = clipboardWriter;
      this.statusChangeCallback = statusChangeCallback;
      this.functionalKeysState = new FunctionalKeysState();
      this.tasks = new ConcurrentLinkedQueue<>();
      this.inputStatus = RemoteSessionInputProcessingStatus.NONE;
      this.status = RemoteSessionInputExtractionStatus.IDLE;
      this.connectionStatus = RemoteSessionInputExtractionConnectionStatus.OPEN;
      this.baseTime = 0L;
   }

   @Override
   public ManagedSession getManagedSession() {
      return this.managedSession;
   }

   @Override
   public RemoteSessionInputProcessingStatus getInputStatus() {
      return this.inputStatus;
   }

   @Override
   public void setInputStatus(RemoteSessionInputProcessingStatus inputStatus) {
      this.inputStatus = inputStatus;
   }

   @Override
   public RemoteSessionInputExtractionStatus getStatus() {
      return this.status;
   }

   @Override
   public void setStatus(RemoteSessionInputExtractionStatus status) {
      this.status = status;
      this.invokeStatusChangeCallback();
   }

   @Override
   public FunctionalKeysState getFunctionalKeyState() {
      return this.functionalKeysState;
   }

   @Override
   public void addNewTask(RemoteSessionInputExtractionTask task) {
      this.tasks.add(task);
      if (this.status.equals(RemoteSessionInputExtractionStatus.IDLE)) {
         this.setStatus(RemoteSessionInputExtractionStatus.READY_TO_PROCESS);
      }
   }

   @Override
   public RemoteSessionInputExtractionTask getNextTask() {
      if (this.tasks.isEmpty()) {
         if (this.connectionStatus.equals(RemoteSessionInputExtractionConnectionStatus.CLOSED)) {
            this.clearIoResources();
         } else {
            this.setStatus(RemoteSessionInputExtractionStatus.IDLE);
         }

         return null;
      } else {
         this.currentProcessingTask = this.tasks.poll();
         return this.currentProcessingTask;
      }
   }

   @Override
   public RemoteSessionInputExtractionTask getCurrentProcessingTask() {
      return this.currentProcessingTask;
   }

   @Override
   public void setBaseTime() {
      this.baseTime = Instant.now().getEpochSecond();
   }

   @Override
   public long getBaseTime() {
      return this.baseTime;
   }

   @Override
   public long getElapsedTime() {
      return this.baseTime == 0L ? 0L : this.currentProcessingTask.getRegistrationTime() - this.baseTime;
   }

   @Override
   public void saveKey(KeyInfo keyInfo) throws IOException {
      this.keyWriter.write(keyInfo);
   }

   @Override
   public void saveClipboard(ClipboardInfo clipboardInfo) throws IOException {
      this.clipboardWriter.write(clipboardInfo);
   }

   @Override
   public void finish() {
      synchronized (this) {
         this.connectionStatus = RemoteSessionInputExtractionConnectionStatus.CLOSED;
      }

      try {
         Thread.sleep(1500L);
      } catch (InterruptedException var3) {
      }

      if (this.tasks.isEmpty()
         && !this.status.equals(RemoteSessionInputExtractionStatus.PROCESSING)
         && !this.status.equals(RemoteSessionInputExtractionStatus.FINISHED)) {
         this.clearIoResources();
      }
   }

   protected void clearIoResources() {
      if (!this.status.equals(RemoteSessionInputExtractionStatus.FINISHED)) {
         this.setStatus(RemoteSessionInputExtractionStatus.FINISHED);

         try {
            this.keyWriter.close();
            this.clipboardWriter.close();
         } catch (IOException var5) {
            this.logError(var5, "closing input writers");
         } finally {
            this.log("Remote session input extraction is finished an resources are cleared");
         }
      }
   }

   protected void log(String message) {
      Connection connection = this.getUnderlyingConnection();
      LOGGER.debug(
         Markers.SESSION,
         "{} for {} session to '{}:{}'. Session-ID: {}",
         message,
         connection.getType().toString(),
         connection.getIpAddress(),
         connection.getPort(),
         this.getManagedSession().getId()
      );
   }

   protected void logError(Exception exception, String description) {
      Connection connection = this.getUnderlyingConnection();
      LOGGER.error(
         Markers.SESSION,
         String.format("Unexpected IO error occurred on %s for {} session to '{}:{}'. Session-ID: {}, Error: {}", description),
         connection.getType().toString(),
         connection.getIpAddress(),
         connection.getPort(),
         this.getManagedSession().getId(),
         exception.getMessage()
      );
   }

   private void invokeStatusChangeCallback() {
      if (this.statusChangeCallback != null) {
         this.statusChangeCallback.onStatusChange(this);
      }
   }
}
