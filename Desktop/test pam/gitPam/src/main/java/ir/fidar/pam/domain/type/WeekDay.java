package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum WeekDay implements PersistentEnum {
   SAT(1),
   SUN(2),
   MON(3),
   TUE(4),
   WED(5),
   THU(6),
   FRI(7);

   private int code;

   private WeekDay(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
