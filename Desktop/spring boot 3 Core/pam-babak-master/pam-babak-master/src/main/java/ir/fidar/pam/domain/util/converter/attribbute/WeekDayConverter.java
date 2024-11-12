package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.WeekDay;

public class WeekDayConverter extends GenericEnumAttributeConverter<WeekDay> {
   public WeekDayConverter() {
      this.enumClass = WeekDay.class;
   }
}
