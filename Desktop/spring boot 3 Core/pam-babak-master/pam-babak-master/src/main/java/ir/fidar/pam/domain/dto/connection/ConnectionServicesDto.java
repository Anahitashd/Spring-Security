package ir.fidar.pam.domain.dto.connection;

import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerDetailsDto;
import java.util.List;

public class ConnectionServicesDto {
   private List<BannerDetailsDto> banners;
   private List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints;

   public List<BannerDetailsDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerDetailsDto> banners) {
      this.banners = banners;
   }

   public List<SessionInputConstraintViolationHandlerDetailsDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }
}
