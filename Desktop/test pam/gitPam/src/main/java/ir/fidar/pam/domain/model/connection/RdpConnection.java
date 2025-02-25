package ir.fidar.pam.domain.model.connection;

import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.RdpConnectionSecurityMode;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ColorDepthConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.RdpConnectionSecuerityModeConverter;
import java.util.HashSet;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_rdp_connection"
)
public class RdpConnection extends FileTransferSupportConnection {
   private static final String CLIENT_NAME = "PAM";
   private static final String SERVER_KEYBOARD_LAYOUT = "en-us-qwerty";
   private static final String PRINTER_NAME = "PAM-Printer";
   @Id
   private Long id;
   @NotNull(
      message = "null.colorDepth"
   )
   @Convert(
      converter = ColorDepthConverter.class
   )
   private ColorDepth colorDepth;
   @NotNull(
      message = "null.securityMode"
   )
   @Convert(
      converter = RdpConnectionSecuerityModeConverter.class
   )
   private RdpConnectionSecurityMode securityMode;
   private boolean trustServerCertificate;
   private boolean attachConsole;
   private boolean enableConsoleAudio;
   private boolean enableTheme;
   private boolean enableWallpaper;
   private boolean enableAnimation;
   private boolean enableFontSmoothing;
   private boolean disableAudio;
   private boolean enablePrinting;
   private boolean enableAudioInput;
   private String clientName = "PAM";
   private String keyboardLayout = "en-us-qwerty";
   private String printerName = "PAM-Printer";
   @Size(
      max = 255,
      message = "gt_max.startupAppName"
   )
   @XssProtected
   private String startupAppName;
   @OneToMany(
      mappedBy = "connection",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   private Set<RdpConnectionRemoteApplication> remoteApplications = new HashSet<>();
   @OneToOne(
      fetch = FetchType.LAZY
   )
   @JoinColumn(
      name = "id"
   )
   @MapsId
   private Connection connection;

   public Long getId() {
      return this.id;
   }

   public ColorDepth getColorDepth() {
      return this.colorDepth;
   }

   public void setColorDepth(ColorDepth colorDepth) {
      this.colorDepth = colorDepth;
   }

   public RdpConnectionSecurityMode getSecurityMode() {
      return this.securityMode;
   }

   public void setSecurityMode(RdpConnectionSecurityMode securityMode) {
      this.securityMode = securityMode;
   }

   public boolean isTrustServerCertificate() {
      return this.trustServerCertificate;
   }

   public void setTrustServerCertificate(boolean trustServerCertificate) {
      this.trustServerCertificate = trustServerCertificate;
   }

   public boolean isAttachConsole() {
      return this.attachConsole;
   }

   public void setAttachConsole(boolean attachConsole) {
      this.attachConsole = attachConsole;
   }

   public boolean isEnableConsoleAudio() {
      return this.enableConsoleAudio;
   }

   public void setEnableConsoleAudio(boolean enableConsoleAudio) {
      this.enableConsoleAudio = enableConsoleAudio;
   }

   public boolean isEnableTheme() {
      return this.enableTheme;
   }

   public void setEnableTheme(boolean enableTheme) {
      this.enableTheme = enableTheme;
   }

   public boolean isEnableWallpaper() {
      return this.enableWallpaper;
   }

   public void setEnableWallpaper(boolean enableWallpaper) {
      this.enableWallpaper = enableWallpaper;
   }

   public boolean isEnableAnimation() {
      return this.enableAnimation;
   }

   public void setEnableAnimation(boolean enableAnimation) {
      this.enableAnimation = enableAnimation;
   }

   public boolean isEnableFontSmoothing() {
      return this.enableFontSmoothing;
   }

   public void setEnableFontSmoothing(boolean enableFontSmoothing) {
      this.enableFontSmoothing = enableFontSmoothing;
   }

   public boolean isDisableAudio() {
      return this.disableAudio;
   }

   public void setDisableAudio(boolean disableAudio) {
      this.disableAudio = disableAudio;
   }

   public boolean isEnablePrinting() {
      return this.enablePrinting;
   }

   public void setEnablePrinting(boolean enablePrinting) {
      this.enablePrinting = enablePrinting;
   }

   public boolean isEnableAudioInput() {
      return this.enableAudioInput;
   }

   public void setEnableAudioInput(boolean enableAudioInput) {
      this.enableAudioInput = enableAudioInput;
   }

   public String getClientName() {
      return this.clientName;
   }

   public String getKeyboardLayout() {
      return this.keyboardLayout;
   }

   public String getPrinterName() {
      return this.printerName;
   }

   public String getStartupAppName() {
      return this.startupAppName;
   }

   public void setStartupAppName(String startupAppName) {
      this.startupAppName = startupAppName;
   }

   public Set<RdpConnectionRemoteApplication> getRemoteApplications() {
      return this.remoteApplications;
   }

   public void addRemoteApplication(RdpConnectionRemoteApplication remoteApplication) {
      this.remoteApplications.add(remoteApplication);
   }

   public void removeRemoteApplication(RdpConnectionRemoteApplication remoteApplication) {
      this.remoteApplications.remove(remoteApplication);
   }

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }
}
