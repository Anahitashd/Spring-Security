package ir.fidar.pam.domain.dto.connection.details;

import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.VncConnectionClipboardEncoding;
import ir.fidar.pam.domain.type.VncConnectionCursorMode;

public class VncConnectionDetailsDto extends ConnectionDetailsDto {
   private ColorDepth colorDepth;
   private boolean readOnly;
   private boolean swapRedBlue;
   private VncConnectionCursorMode cursorMode;
   private VncConnectionClipboardEncoding clipboardEncoding;
   private String repeaterHost;
   private Integer repeaterPort;

   public ColorDepth getColorDepth() {
      return this.colorDepth;
   }

   public void setColorDepth(ColorDepth colorDepth) {
      this.colorDepth = colorDepth;
   }

   public boolean isReadOnly() {
      return this.readOnly;
   }

   public void setReadOnly(boolean readOnly) {
      this.readOnly = readOnly;
   }

   public boolean isSwapRedBlue() {
      return this.swapRedBlue;
   }

   public void setSwapRedBlue(boolean swapRedBlue) {
      this.swapRedBlue = swapRedBlue;
   }

   public VncConnectionCursorMode getCursorMode() {
      return this.cursorMode;
   }

   public void setCursorMode(VncConnectionCursorMode cursorMode) {
      this.cursorMode = cursorMode;
   }

   public VncConnectionClipboardEncoding getClipboardEncoding() {
      return this.clipboardEncoding;
   }

   public void setClipboardEncoding(VncConnectionClipboardEncoding clipboardEncoding) {
      this.clipboardEncoding = clipboardEncoding;
   }

   public String getRepeaterHost() {
      return this.repeaterHost;
   }

   public void setRepeaterHost(String repeaterHost) {
      this.repeaterHost = repeaterHost;
   }

   public Integer getRepeaterPort() {
      return this.repeaterPort;
   }

   public void setRepeaterPort(Integer repeaterPort) {
      this.repeaterPort = repeaterPort;
   }
}
