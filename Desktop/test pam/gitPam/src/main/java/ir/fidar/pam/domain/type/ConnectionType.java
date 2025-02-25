package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum ConnectionType implements PersistentEnum {
   SSH(1),
   RDP(2),
   VNC(3),
   TELNET(4);

   private int code;

   private ConnectionType(int code) {
      this.code = code;
   }

   @Override
   public int getCode() {
      return this.code;
   }
}
