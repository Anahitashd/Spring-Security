package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum SessionTransferredFileStatus implements PersistentEnum {
   SUCCESSFUL(1),
   ACCESS_DENIED(2),
   SYSTEM_ERROR(3),
   SESSION_NOT_FOUND(4),
   MALWARE(5);

   private final int code;

   private SessionTransferredFileStatus(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
