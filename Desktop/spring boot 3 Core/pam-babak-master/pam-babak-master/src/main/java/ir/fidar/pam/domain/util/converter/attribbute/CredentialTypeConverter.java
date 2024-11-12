package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.CredentialType;

public class CredentialTypeConverter extends GenericEnumAttributeConverter<CredentialType> {
   public CredentialTypeConverter() {
      this.enumClass = CredentialType.class;
   }
}
