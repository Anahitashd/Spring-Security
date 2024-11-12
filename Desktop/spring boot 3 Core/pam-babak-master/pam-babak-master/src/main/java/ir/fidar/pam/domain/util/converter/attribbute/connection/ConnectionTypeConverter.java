package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.ConnectionType;

public class ConnectionTypeConverter extends GenericEnumAttributeConverter<ConnectionType> {
   public ConnectionTypeConverter() {
      this.enumClass = ConnectionType.class;
   }
}
