package ir.fidar.pam.session.inputextraction.processor.extractor.common;

import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.KeysymUtility;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.KeyType;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeyExtractor implements InputExtractor<KeyInfo> {
   private static final Logger LOGGER = LogManager.getLogger();

   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return instruction.getOpcode().equalsIgnoreCase("key");
   }

   public KeyInfo extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      int keysym = Integer.parseInt((String)instruction.getArgs().get(0));
      boolean pressed = ((String)instruction.getArgs().get(1)).equals("1");
      KeysymUtility.KeyInfo keyInfo = KeysymUtility.resolveKey(keysym);
      if (keyInfo == null) {
         LOGGER.debug(Markers.SESSION, "Could not find key info for keysym '{}'", keysym);
         return null;
      } else {
         String character = keyInfo.getType().equals(KeyType.CHAR) ? new String(Character.toChars(keyInfo.getUnicode())) : null;
         return new KeyInfo(
            keyInfo.getKeysym(),
            keyInfo.getUnicode(),
            KeysymUtility.convertToReadable(keyInfo.getNames()[0]),
            character,
            pressed,
            remoteSessionInputExtraction.getElapsedTime(),
            keyInfo.getType()
         );
      }
   }
}
