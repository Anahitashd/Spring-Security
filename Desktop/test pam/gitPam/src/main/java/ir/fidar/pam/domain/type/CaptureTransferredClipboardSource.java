package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum CaptureTransferredClipboardSource implements PersistentEnum {
   CLIENT(1),
   SERVER(2);

   private final int code;

   private CaptureTransferredClipboardSource(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
