package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum ColorScheme implements PersistentEnum {
   BLACK_WHITE(1, "black-white"),
   GRAY_BLACK(2, "gray-black"),
   GREEN_BLACK(3, "green-black"),
   WHITE_BLACK(4, "white-black");

   private int code;
   private String asParameterName;

   private ColorScheme(int code, String asParameterName) {
      this.code = code;
      this.asParameterName = asParameterName;
   }

   @Override
   public int getCode() {
      return this.code;
   }

   public String getAsParameterName() {
      return this.asParameterName;
   }
}
