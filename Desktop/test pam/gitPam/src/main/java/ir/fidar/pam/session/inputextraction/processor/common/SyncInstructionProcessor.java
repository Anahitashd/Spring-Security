package ir.fidar.pam.session.inputextraction.processor.common;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.AbstractCommonSessionTypeInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.common.SyncExtractor;

public class SyncInstructionProcessor extends AbstractCommonSessionTypeInstructionProcessor<Long> {
   @Override
   protected InputExtractor<Long> getExtractor() {
      return new SyncExtractor();
   }

   protected void processExtractedInput(Long input, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      if (remoteSessionInputExtraction.getBaseTime() == 0L) {
         remoteSessionInputExtraction.setBaseTime();
         remoteSessionInputExtraction.setInputStatus(RemoteSessionInputProcessingStatus.NONE);
      }
   }

   public int getOrder() {
      return 20;
   }
}
