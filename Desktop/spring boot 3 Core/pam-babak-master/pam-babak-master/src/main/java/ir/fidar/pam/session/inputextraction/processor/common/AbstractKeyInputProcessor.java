package ir.fidar.pam.session.inputextraction.processor.common;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.SpecialKeys;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.AbstractOrderedSessionTypeAwareInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import ir.fidar.pam.session.inputextraction.processor.extractor.common.KeyExtractor;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class AbstractKeyInputProcessor<T extends RemoteSessionInputExtraction> extends AbstractOrderedSessionTypeAwareInstructionProcessor<KeyInfo, T> {
   private static final Logger LOGGER = LogManager.getLogger();

   protected abstract void finalizeProcessing(KeyInfo var1, InputSource var2, T var3) throws Exception;

   @Override
   protected InputExtractor<KeyInfo> getExtractor() {
      return new KeyExtractor();
   }

   protected void processExtractedInput(KeyInfo keyInfo, InputSource source, T remoteSessionInputExtraction) {
      if (keyInfo != null) {
         Connection connection = remoteSessionInputExtraction.getUnderlyingConnection();
         int keysym = keyInfo.getKeysym();

         try {
            if (SpecialKeys.SHIFT.getX11Coeds().contains(keysym)) {
               if (keyInfo.isPressed()) {
                  remoteSessionInputExtraction.getFunctionalKeyState().getShift().set();
               } else {
                  remoteSessionInputExtraction.getFunctionalKeyState().getShift().reset();
               }
            } else if (SpecialKeys.CTRL.getX11Coeds().contains(keysym)) {
               if (keyInfo.isPressed()) {
                  remoteSessionInputExtraction.getFunctionalKeyState().getCtrl().set();
               } else {
                  remoteSessionInputExtraction.getFunctionalKeyState().getCtrl().reset();
               }
            }

            this.finalizeProcessing(keyInfo, source, remoteSessionInputExtraction);
         } catch (Exception var7) {
            LOGGER.error(
               Markers.SESSION,
               "Unexpected error occurred on processing key input on {} session to '{}:{}'. Session-ID: {}",
               connection.getType().toString(),
               connection.getIpAddress(),
               connection.getPort(),
               remoteSessionInputExtraction.getManagedSession().getId(),
               var7
            );
         }
      }
   }

   public int getOrder() {
      return 1;
   }
}
