package ir.fidar.pam.domain.util.converter.attribbute.connection;

import ir.fidar.core.domain.util.converter.attribute.GenericEnumAttributeConverter;
import ir.fidar.pam.domain.type.VncConnectionClipboardEncoding;

public class VncConnectionClipboardEncodingConverter extends GenericEnumAttributeConverter<VncConnectionClipboardEncoding> {
   public VncConnectionClipboardEncodingConverter() {
      this.enumClass = VncConnectionClipboardEncoding.class;
   }
}
