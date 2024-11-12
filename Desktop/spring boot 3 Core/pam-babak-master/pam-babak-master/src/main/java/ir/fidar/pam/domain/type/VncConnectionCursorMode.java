package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum VncConnectionCursorMode implements PersistentEnum {
   LOCAL(1),
   REMOTE(2);

   private int code;

   private VncConnectionCursorMode(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
