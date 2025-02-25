package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.ColorScheme;

public class ColorSchemeConverter extends GenericEnumAttributeConverter<ColorScheme> {
   public ColorSchemeConverter() {
      this.enumClass = ColorScheme.class;
   }
}
