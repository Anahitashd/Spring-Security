package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.pam.session.OcrHttpClient;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.consoletype.InputImageBlobExtractor;

public class InputImageBlobInstructionProcessor extends AbstractConsoleTypeInstructionProcessor<String> {
   private final OcrHttpClient ocrHttpClient;

   public InputImageBlobInstructionProcessor(OcrHttpClient ocrHttpClient) {
      this.ocrHttpClient = ocrHttpClient;
   }

   @Override
   protected InputExtractor<String> getExtractor() {
      return new InputImageBlobExtractor();
   }

   protected void processExtractedInput(String imageContent, InputSource source, ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) {
      try {
         String extractedText = this.ocrHttpClient.sendExtractionRequest(imageContent, 7, OcrHttpClient.Dataset.LEGACY, 0, null, true);
         if (remoteSessionInputExtraction.isTabPressed() && extractedText != null) {
            remoteSessionInputExtraction.appendToCommand(extractedText);
         }

         remoteSessionInputExtraction.processResolvableInputs(extractedText);
         remoteSessionInputExtraction.setInputStatus(ConsoleTypeRemoteSessionInputProcessingStatus.NONE);
      } catch (Exception var5) {
         var5.printStackTrace();
      }
   }

   public int getOrder() {
      return 5;
   }
}
