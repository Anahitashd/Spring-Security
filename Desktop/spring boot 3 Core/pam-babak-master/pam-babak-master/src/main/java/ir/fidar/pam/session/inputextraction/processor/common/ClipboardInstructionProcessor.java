package ir.fidar.pam.session.inputextraction.processor.common;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.AbstractCommonSessionTypeInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.common.ClipboardExtractor;

public class ClipboardInstructionProcessor extends AbstractCommonSessionTypeInstructionProcessor<Void> {
   @Override
   protected InputExtractor<Void> getExtractor() {
      return new ClipboardExtractor();
   }

   protected void processExtractedInput(Void input, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      remoteSessionInputExtraction.setInputStatus(RemoteSessionInputProcessingStatus.CLIPBOARD);
   }

   public int getOrder() {
      return 15;
   }
}
