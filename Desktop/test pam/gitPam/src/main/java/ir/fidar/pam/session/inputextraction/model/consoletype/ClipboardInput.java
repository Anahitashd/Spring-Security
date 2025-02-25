package ir.fidar.pam.session.inputextraction.model.consoletype;

import ir.fidar.core.util.StringUtils;

public class ClipboardInput extends AbstractResolvableInput<String> {
   public ClipboardInput(ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction, String content) {
      super(remoteSessionInputExtraction, content);
   }

   @Override
   public boolean isComparable() {
      return true;
   }

   @Override
   public boolean matchesContent(String imageContent) {
      return StringUtils.hasContent(imageContent) && this.remoteSessionInputExtraction.getLastTransmittedClipboard().equalsIgnoreCase(this.getContent())
         || this.remoteSessionInputExtraction.getLastTransmittedClipboard().toLowerCase().contains(this.getContent().toLowerCase());
   }

   @Override
   public void resolve() {
      this.remoteSessionInputExtraction.appendToCommand(this.getContent());
   }

   @Override
   public String toString() {
      return (String)super.getContent();
   }
}
