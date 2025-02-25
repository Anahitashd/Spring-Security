package ir.fidar.pam.session.inputextraction.model.consoletype;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;

public interface ConsoleTypeRemoteSessionInputExtraction extends RemoteSessionInputExtraction {
   void addResolvableInput(ResolvableInput var1);

   void processResolvableInputs(String var1);

   void setLastTransmittedClipboard(String var1);

   String getLastTransmittedClipboard();

   void clearCommandBuffer();

   void appendToCommand(String var1);

   void removeLastCharacterFromCommandBuffer();

   void flushCommandBuffer();

   boolean isTabPressed();
}
