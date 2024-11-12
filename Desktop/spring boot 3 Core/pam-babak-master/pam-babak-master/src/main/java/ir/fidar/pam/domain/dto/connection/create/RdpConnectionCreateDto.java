package ir.fidar.pam.domain.dto.connection.create;

import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationCreateDto;
import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.RdpConnectionSecurityMode;
import java.util.Set;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class RdpConnectionCreateDto extends FileTransferSupportConnectionCreateDto {
   @NotNull(
      message = "null.colorDepth"
   )
   private ColorDepth colorDepth;
   @NotNull(
      message = "null.securityMode"
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
   @Size(
      max = 255,
      message = "gt_max.startupAppName"
   )
   @XssProtected
   private String startupAppName;
   private Set<RdpConnectionRemoteApplicationCreateDto> remoteApplications;

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

   public String getStartupAppName() {
      return this.startupAppName;
   }

   public void setStartupAppName(String startupAppName) {
      this.startupAppName = startupAppName;
   }

   public Set<RdpConnectionRemoteApplicationCreateDto> getRemoteApplications() {
      return this.remoteApplications;
   }

   public void setRemoteApplications(Set<RdpConnectionRemoteApplicationCreateDto> remoteApplications) {
      this.remoteApplications = remoteApplications;
   }
}
