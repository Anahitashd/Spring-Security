package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum FileTransferMode implements PersistentEnum {
   NONE(1),
   DOWNLOAD(2),
   UPLOAD(3),
   BOTH(4);

   private int code;

   private FileTransferMode(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
