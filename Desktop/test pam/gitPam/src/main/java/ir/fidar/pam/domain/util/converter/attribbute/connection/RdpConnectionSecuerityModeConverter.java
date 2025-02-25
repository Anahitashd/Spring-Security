package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.RdpConnectionSecurityMode;

public class RdpConnectionSecuerityModeConverter extends GenericEnumAttributeConverter<RdpConnectionSecurityMode> {
   public RdpConnectionSecuerityModeConverter() {
      this.enumClass = RdpConnectionSecurityMode.class;
   }
}
