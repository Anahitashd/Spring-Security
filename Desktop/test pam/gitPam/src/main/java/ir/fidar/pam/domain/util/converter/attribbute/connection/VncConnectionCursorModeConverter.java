package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.VncConnectionCursorMode;

public class VncConnectionCursorModeConverter extends GenericEnumAttributeConverter<VncConnectionCursorMode> {
   public VncConnectionCursorModeConverter() {
      this.enumClass = VncConnectionCursorMode.class;
   }
}
