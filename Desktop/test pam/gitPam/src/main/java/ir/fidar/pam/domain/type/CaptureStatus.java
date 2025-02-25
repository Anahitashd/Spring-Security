package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum CaptureStatus implements PersistentEnum {
   LIVE(1),
   CLOSED(2);

   private final int code;

   private CaptureStatus(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
