package ir.fidar.pam.session.inputextraction.service.tasks;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionExtractionTaskRegistry;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.callback.InputExtractionTaskFinishCallback;
import ir.fidar.pam.session.inputextraction.processor.InstructionProcessingService;

public class ExtractionTaskRegistrationTask extends SynchronizedTask {
   private final RemoteSessionExtractionTaskRegistry extractionTaskRegistry;
   private final InstructionProcessingService instructionProcessingService;
   private final InputExtractionTaskFinishCallback inputExtractionTaskFinishCallback;

   public ExtractionTaskRegistrationTask(
      RemoteSessionInputExtraction remoteSessionInputExtraction,
      RemoteSessionExtractionTaskRegistry extractionTaskRegistry,
      InstructionProcessingService instructionProcessingService,
      InputExtractionTaskFinishCallback inputExtractionTaskFinishCallback
   ) {
      super(remoteSessionInputExtraction);
      this.extractionTaskRegistry = extractionTaskRegistry;
      this.instructionProcessingService = instructionProcessingService;
      this.inputExtractionTaskFinishCallback = inputExtractionTaskFinishCallback;
   }

   @Override
   public void run() {
      this.getBoundedRemoteSessionInputExtraction()
         .addNewTask(
            new RemoteSessionInputExtractionTask(
               this.getBoundedRemoteSessionInputExtraction(),
               this.extractionTaskRegistry,
               this.instructionProcessingService,
               this.inputExtractionTaskFinishCallback
            )
         );
   }
}
