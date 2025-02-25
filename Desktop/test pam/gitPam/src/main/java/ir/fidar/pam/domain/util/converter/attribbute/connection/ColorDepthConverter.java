package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.ColorDepth;

public class ColorDepthConverter extends GenericEnumAttributeConverter<ColorDepth> {
   public ColorDepthConverter() {
      this.enumClass = ColorDepth.class;
   }
}
