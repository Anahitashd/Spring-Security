package ir.fidar.pam.session.inputextraction.model;

import java.util.Objects;

public class RemoteSessionInputProcessingStatus {
   public static final RemoteSessionInputProcessingStatus NONE = new RemoteSessionInputProcessingStatus("none");
   public static final RemoteSessionInputProcessingStatus CLIPBOARD = new RemoteSessionInputProcessingStatus("clipboard");
   private final String code;

   protected RemoteSessionInputProcessingStatus(String code) {
      this.code = code;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         RemoteSessionInputProcessingStatus that = (RemoteSessionInputProcessingStatus)o;
         return this.code.equals(that.code);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.code);
   }
}
