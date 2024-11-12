package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum AccessibilityTimePeriodMode implements PersistentEnum {
   DAILY(1),
   WEEKLY(2),
   MONTHLY(3);

   private int code;

   private AccessibilityTimePeriodMode(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
