package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.consoletype.KeyInput;
import ir.fidar.pam.session.inputextraction.processor.SessionType;
import ir.fidar.pam.session.inputextraction.processor.common.AbstractKeyInputProcessor;
import java.util.Set;

public class KeyInputProcessor extends AbstractKeyInputProcessor<ConsoleTypeRemoteSessionInputExtraction> {
   protected void finalizeProcessing(KeyInfo keyInfo, InputSource source, ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) throws CloneNotSupportedException {
      if (keyInfo.isPressed()) {
         remoteSessionInputExtraction.addResolvableInput(new KeyInput(remoteSessionInputExtraction, keyInfo));
         remoteSessionInputExtraction.setInputStatus(RemoteSessionInputProcessingStatus.NONE);
      }
   }

   @Override
   public Set<ConnectionType> getSessionTypes() {
      return SessionType.CONSOLE.getConnectionTypes();
   }
}
