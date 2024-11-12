package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum ColorDepth implements PersistentEnum {
   CD_8(1, 8),
   CD_16(2, 16),
   CD_24(3, 24);

   private int code;
   private int asInteger;

   private ColorDepth(int code, int asInteger) {
      this.code = code;
      this.asInteger = asInteger;
   }

   @Override
   public int getCode() {
      return this.code;
   }

   public int getAsInteger() {
      return this.asInteger;
   }
}
