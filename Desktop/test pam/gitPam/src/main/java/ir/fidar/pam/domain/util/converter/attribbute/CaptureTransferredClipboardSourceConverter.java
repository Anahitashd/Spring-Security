package ir.fidar.pam.domain.util.converter.attribbute;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.CaptureTransferredClipboardSource;

public class CaptureTransferredClipboardSourceConverter extends GenericEnumAttributeConverter<CaptureTransferredClipboardSource> {
   public CaptureTransferredClipboardSourceConverter() {
      this.enumClass = CaptureTransferredClipboardSource.class;
   }
}
