package ir.fidar.pam.domain.dto.connection.create;

import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.VncConnectionClipboardEncoding;
import ir.fidar.pam.domain.type.VncConnectionCursorMode;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class VncConnectionCreateDto extends ConnectionUpdateDto {
   @NotNull(
      message = "null.colorDepth"
   )
   private ColorDepth colorDepth;
   private boolean readOnly;
   private boolean swapRedBlue;
   @NotNull(
      message = "null.cursorMode"
   )
   private VncConnectionCursorMode cursorMode;
   @NotNull(
      message = "null.clipboardEncoding"
   )
   private VncConnectionClipboardEncoding clipboardEncoding;
   @Size(
      max = 255,
      message = "gt_max.repeaterHost"
   )
   private String repeaterHost;
   @Min(
      value = 1L,
      message = "lt_min.repeaterPort"
   )
   @Max(
      value = 65535L,
      message = "gt_max.repeaterPort"
   )
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
