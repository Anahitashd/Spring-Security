package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.consoletype.ClipboardInput;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.consoletype.RightMouseClickExtractor;

public class MouseRightClickInstructionProcessor extends AbstractConsoleTypeInstructionProcessor<Void> {
   @Override
   protected InputExtractor<Void> getExtractor() {
      return new RightMouseClickExtractor();
   }

   protected void processExtractedInput(Void input, InputSource source, ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) {
      String clipboard = remoteSessionInputExtraction.getLastTransmittedClipboard();
      String[] lines = StringUtils.split(clipboard, "\n");

      for (String line : lines) {
         remoteSessionInputExtraction.addResolvableInput(new ClipboardInput(remoteSessionInputExtraction, line));
      }

      remoteSessionInputExtraction.setInputStatus(ConsoleTypeRemoteSessionInputProcessingStatus.NONE);
   }

   public int getOrder() {
      return 6;
   }
}
