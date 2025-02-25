package ir.fidar.pam.domain.type;

public enum UserAuthenticationMode {
   INTERNALLY((byte)1),
   EXTERNALLY((byte)2);

   private byte code;

   private UserAuthenticationMode(byte code) {
      this.code = code;
   }

   public byte getCode() {
      return this.code;
   }

   public static UserAuthenticationMode getMode(byte code) {
      if (code == INTERNALLY.getCode()) {
         return INTERNALLY;
      } else {
         return code == EXTERNALLY.getCode() ? EXTERNALLY : null;
      }
   }
}
