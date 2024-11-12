package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum SessionTransferFileMode implements PersistentEnum {
   DOWNLOAD(1),
   UPLOAD(2);

   private int code;

   private SessionTransferFileMode(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
