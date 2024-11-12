package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import java.util.List;

public class AccessRuleConditionInfoDto {
   private boolean clipboardSupported;
   private boolean downloadSupported;
   private boolean uploadSupported;
   private boolean credentialRequired;
   private boolean rememberMeActivated;
   private List<BannerDetailsDto> banners;
   private ConnectionInfoDto connectionInfo;

   public boolean isClipboardSupported() {
      return this.clipboardSupported;
   }

   public void setClipboardSupported(boolean clipboardSupported) {
      this.clipboardSupported = clipboardSupported;
   }

   public boolean isDownloadSupported() {
      return this.downloadSupported;
   }

   public void setDownloadSupported(boolean downloadSupported) {
      this.downloadSupported = downloadSupported;
   }

   public boolean isUploadSupported() {
      return this.uploadSupported;
   }

   public void setUploadSupported(boolean uploadSupported) {
      this.uploadSupported = uploadSupported;
   }

   public boolean isCredentialRequired() {
      return this.credentialRequired;
   }

   public void setCredentialRequired(boolean credentialRequired) {
      this.credentialRequired = credentialRequired;
   }

   public boolean isRememberMeActivated() {
      return this.rememberMeActivated;
   }

   public void setRememberMeActivated(boolean rememberMeActivated) {
      this.rememberMeActivated = rememberMeActivated;
   }

   public List<BannerDetailsDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerDetailsDto> banners) {
      this.banners = banners;
   }

   public ConnectionInfoDto getConnectionInfo() {
      return this.connectionInfo;
   }

   public void setConnectionInfo(ConnectionInfoDto connectionInfo) {
      this.connectionInfo = connectionInfo;
   }
}
