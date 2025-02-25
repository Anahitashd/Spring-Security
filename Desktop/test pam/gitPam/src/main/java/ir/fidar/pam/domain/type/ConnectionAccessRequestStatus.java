package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum ConnectionAccessRequestStatus implements PersistentEnum {
   NOT_CHECKED(1),
   APPROVED(2),
   DISAPPROVED(3);

   private int code;

   private ConnectionAccessRequestStatus(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
