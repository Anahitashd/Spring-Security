package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public abstract class AbstractOrderedSessionTypeAwareInstructionProcessor<T, K extends RemoteSessionInputExtraction>
   implements OrderedSessionTypeAwareInstructionProcessor<K> {
   protected abstract InputExtractor<T> getExtractor();

   protected abstract void processExtractedInput(T var1, InputSource var2, K var3);

   @Override
   public boolean processInput(GuacamoleInstruction input, InputSource source, K remoteSessionInputExtraction) {
      InputExtractor<T> extractor = this.getExtractor();
      if (extractor == null) {
         throw new IllegalStateException("Extractor must be provided");
      } else if (extractor.extractable(input, remoteSessionInputExtraction)) {
         T extractedInput = extractor.extract(input, remoteSessionInputExtraction);
         this.processExtractedInput(extractedInput, source, remoteSessionInputExtraction);
         return true;
      } else {
         return false;
      }
   }
}
