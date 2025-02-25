package ir.fidar.pam.domain.dto.connection.details;

import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationDetailsDto;
import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.RdpConnectionSecurityMode;
import java.util.List;

public class RdpConnectionDetailsDto extends FileTransferSupportConnectionDetailsDto {
   private ColorDepth colorDepth;
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
   private String startupAppName;
   private List<RdpConnectionRemoteApplicationDetailsDto> remoteApplications;

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

   public List<RdpConnectionRemoteApplicationDetailsDto> getRemoteApplications() {
      return this.remoteApplications;
   }

   public void setRemoteApplications(List<RdpConnectionRemoteApplicationDetailsDto> remoteApplications) {
      this.remoteApplications = remoteApplications;
   }
}
