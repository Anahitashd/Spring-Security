package ir.fidar.pam.session.inputextraction.service.tasks;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionExtractionTaskRegistry;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.callback.InputExtractionTaskFinishCallback;
import ir.fidar.pam.session.inputextraction.processor.InstructionProcessingService;
import java.io.StringReader;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.io.ReaderGuacamoleReader;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RemoteSessionInputExtractionTask extends SynchronizedTask {
   private static final Logger LOGGER = LogManager.getLogger();
   private final RemoteSessionExtractionTaskRegistry task;
   private final InstructionProcessingService instructionProcessingService;
   private final InputExtractionTaskFinishCallback finishCallback;

   public RemoteSessionInputExtractionTask(
      RemoteSessionInputExtraction remoteSessionInputExtraction,
      RemoteSessionExtractionTaskRegistry task,
      InstructionProcessingService instructionProcessingService,
      InputExtractionTaskFinishCallback finishCallback
   ) {
      super(remoteSessionInputExtraction);
      this.task = task;
      this.instructionProcessingService = instructionProcessingService;
      this.finishCallback = finishCallback;
   }

   @Override
   public void run() {
      String input = this.task.getInput();
      GuacamoleReader guacamoleReader = new ReaderGuacamoleReader(new StringReader(input));
      Connection connection = this.getBoundedRemoteSessionInputExtraction().getUnderlyingConnection();

      try {
         GuacamoleInstruction instruction;
         try {
            while ((instruction = guacamoleReader.readInstruction()) != null) {
               this.instructionProcessingService.process(instruction, this.task.getInputSource(), this.getBoundedRemoteSessionInputExtraction());
            }
         } catch (GuacamoleException var9) {
            LOGGER.error(
               Markers.SESSION,
               "Unexpected error occurred on reading bridge instructions for input extraction processing for {} session to '{}:{}'. Session-ID: {}",
               connection.getType().toString(),
               connection.getIpAddress(),
               connection.getPort(),
               this.getBoundedRemoteSessionInputExtraction().getManagedSession().getId(),
               var9
            );
         }
      } finally {
         if (this.finishCallback != null) {
            this.finishCallback.onFinish(this.getBoundedRemoteSessionInputExtraction());
         }
      }
   }
}
