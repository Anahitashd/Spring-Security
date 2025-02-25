package ir.fidar.pam.session.inputextraction.processor.graphicaltype;

import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;
import ir.fidar.pam.session.inputextraction.processor.SessionType;
import ir.fidar.pam.session.inputextraction.processor.common.AbstractKeyInputProcessor;
import java.io.IOException;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyInputProcessor extends AbstractKeyInputProcessor<RemoteSessionInputExtraction> {
   private static final Logger LOGGER = LogManager.getLogger();

   @Override
   protected void finalizeProcessing(KeyInfo keyInfo, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) throws CloneNotSupportedException {
      try {
         if (keyInfo.isPressed()) {
            remoteSessionInputExtraction.saveKey(keyInfo);
            remoteSessionInputExtraction.setInputStatus(RemoteSessionInputProcessingStatus.NONE);
         }
      } catch (IOException var6) {
         Connection connection = remoteSessionInputExtraction.getManagedSession().getConnection();
         LOGGER.error(
            Markers.SESSION,
            "Unexpected error occurred on flushing session input for {} session to '{}:{}'. Session-ID: {}, Error: {}",
            connection.getType().toString(),
            connection.getIpAddress(),
            connection.getPort(),
            remoteSessionInputExtraction.getManagedSession().getId(),
            var6.getMessage()
         );
      }
   }

   @Override
   public Set<ConnectionType> getSessionTypes() {
      return SessionType.GRAPHICAL.getConnectionTypes();
   }
}
