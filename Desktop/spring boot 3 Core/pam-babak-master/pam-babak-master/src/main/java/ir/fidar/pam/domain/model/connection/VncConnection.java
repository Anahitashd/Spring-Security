package ir.fidar.pam.domain.model.connection;

import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.VncConnectionClipboardEncoding;
import ir.fidar.pam.domain.type.VncConnectionCursorMode;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ColorDepthConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.VncConnectionClipboardEncodingConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.VncConnectionCursorModeConverter;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(
   name = "tb_vnc_connection"
)
public class VncConnection {
   @Id
   private Long id;
   @NotNull(
      message = "null.colorDepth"
   )
   @Convert(
      converter = ColorDepthConverter.class
   )
   private ColorDepth colorDepth;
   private boolean readOnly;
   private boolean swapRedBlue;
   @NotNull(
      message = "null.cursorMode"
   )
   @Convert(
      converter = VncConnectionCursorModeConverter.class
   )
   private VncConnectionCursorMode cursorMode;
   @NotNull(
      message = "null.clipboardEncoding"
   )
   @Convert(
      converter = VncConnectionClipboardEncodingConverter.class
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
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "id"
   )
   @MapsId
   private Connection connection;

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

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }

   @Override
   public boolean equals(Object o) {
      return super.equals(o);
   }

   @Override
   public int hashCode() {
      return super.hashCode();
   }
}
