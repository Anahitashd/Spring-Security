package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum VncConnectionClipboardEncoding implements PersistentEnum {
   ISO8859_1(1, "ISO8859-1"),
   UTF8(2, "UTF-8"),
   UTF16(3, "UTF-16"),
   CP1252(4, "CP1252");

   private int code;
   private String asParameterName;

   private VncConnectionClipboardEncoding(int code, String asParameterName) {
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
