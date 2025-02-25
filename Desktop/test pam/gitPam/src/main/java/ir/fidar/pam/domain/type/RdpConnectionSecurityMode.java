package ir.fidar.pam.domain.type;

import ir.fidar.core.domain.type.PersistentEnum;

public enum RdpConnectionSecurityMode implements PersistentEnum {
   ANY(1, "any"),
   NLA(2, "nla"),
   NLA_EXT(3, "nla-ext"),
   TLS(4, "tls"),
   RDP(5, "rdp"),
   VMCONNECT(6, "vmconnect");

   private int code;
   private String asParameterName;

   private RdpConnectionSecurityMode(int code, String asParameterName) {
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
