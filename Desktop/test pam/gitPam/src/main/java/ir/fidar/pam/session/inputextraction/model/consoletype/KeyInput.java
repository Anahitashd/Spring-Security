package ir.fidar.pam.session.inputextraction.model.consoletype;

import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.session.inputextraction.SpecialKeys;
import ir.fidar.pam.session.inputextraction.model.FunctionalKeysState;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.KeyType;

public class KeyInput extends AbstractResolvableInput<KeyInfo> {
   private final FunctionalKeysState functionalKeysState;

   public KeyInput(ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction, KeyInfo keyInfo) throws CloneNotSupportedException {
      super(remoteSessionInputExtraction, keyInfo);
      this.functionalKeysState = (FunctionalKeysState)remoteSessionInputExtraction.getFunctionalKeyState().clone();
   }

   public FunctionalKeysState getFunctionalKeysState() {
      return this.functionalKeysState;
   }

   @Override
   public boolean isComparable() {
      return this.getContent().getType().equals(KeyType.CHAR);
   }

   @Override
   public boolean matchesContent(String imageContent) {
      if (!StringUtils.hasContent(imageContent)) {
         return false;
      } else if (!SpecialKeys.L.getX11Coeds().contains(this.getContent().getKeysym())) {
         return SpecialKeys.C.getX11Coeds().contains(this.getContent().getKeysym()) && this.functionalKeysState.getCtrl().isPressed()
            ? imageContent.equalsIgnoreCase("AC")
            : imageContent.equalsIgnoreCase(this.getContent().getCharacter());
      } else {
         return imageContent.equalsIgnoreCase(this.getContent().getCharacter()) || imageContent.equalsIgnoreCase("1");
      }
   }

   @Override
   public void resolve() throws Exception {
      this.remoteSessionInputExtraction.saveKey(this.getContent());
      int keysym = this.getContent().getKeysym();
      if (SpecialKeys.BACK_SPACE.getX11Coeds().contains(keysym)) {
         this.remoteSessionInputExtraction.removeLastCharacterFromCommandBuffer();
      } else if (SpecialKeys.ENTER.getX11Coeds().contains(keysym)) {
         this.remoteSessionInputExtraction.flushCommandBuffer();
      } else if (SpecialKeys.C.getX11Coeds().contains(this.getContent().getKeysym()) && this.functionalKeysState.getCtrl().isPressed()) {
         this.remoteSessionInputExtraction.clearCommandBuffer();
      } else if (this.getContent().getType().equals(KeyType.CHAR)) {
         this.remoteSessionInputExtraction.appendToCommand(this.getContent().getCharacter());
      }
   }

   @Override
   public String toString() {
      return ((KeyInfo)super.getContent()).getName();
   }
}
