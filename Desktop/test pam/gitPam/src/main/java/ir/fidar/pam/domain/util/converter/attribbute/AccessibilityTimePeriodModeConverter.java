package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;

public class AccessibilityTimePeriodModeConverter extends GenericEnumAttributeConverter<AccessibilityTimePeriodMode> {
   public AccessibilityTimePeriodModeConverter() {
      this.enumClass = AccessibilityTimePeriodMode.class;
   }
}
