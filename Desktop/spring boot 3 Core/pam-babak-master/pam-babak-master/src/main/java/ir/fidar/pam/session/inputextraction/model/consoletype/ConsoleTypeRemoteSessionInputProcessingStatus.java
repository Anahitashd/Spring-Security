package ir.fidar.pam.session.inputextraction.model.consoletype;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputProcessingStatus;

public class ConsoleTypeRemoteSessionInputProcessingStatus extends RemoteSessionInputProcessingStatus {
   public static final RemoteSessionInputProcessingStatus IMAGE_RECT = new ConsoleTypeRemoteSessionInputProcessingStatus("image-rect");
   public static final RemoteSessionInputProcessingStatus IMAGE_CFILL = new ConsoleTypeRemoteSessionInputProcessingStatus("image-cfill");
   public static final RemoteSessionInputProcessingStatus IMAGE_IMG = new ConsoleTypeRemoteSessionInputProcessingStatus("image-img");

   private ConsoleTypeRemoteSessionInputProcessingStatus(String code) {
      super(code);
   }
}
