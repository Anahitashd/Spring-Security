package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.CaptureStatus;

public class CaptureStatusConverter extends GenericEnumAttributeConverter<CaptureStatus> {
   public CaptureStatusConverter() {
      this.enumClass = CaptureStatus.class;
   }
}
