package ir.fidar.pam.domain.dto.connectionaccessrequest;

import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.CustomizedXssProtected;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.credential.create.CredentialCreateDto;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Size;

public class ConnectionAccessRequestReviewDto {
   private boolean approved;
   @CustomizedXssProtected(
      skippingCharacters = {','}
   )
   @Size(
      max = 255,
      message = "gt_max.note"
   )
   private String note;
   @ValidName(
      notBlank = false
   )
   @Size(
      max = 48,
      message = "gt_max.connectionName"
   )
   @XssProtected
   private String accessRuleName;
   @Valid
   private CredentialCreateDto credential;
   private List<BannerCreateDto> banners;
   private List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints;
   @Valid
   private AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint;

   public boolean isApproved() {
      return this.approved;
   }

   public void setApproved(boolean approved) {
      this.approved = approved;
   }

   public String getNote() {
      return this.note;
   }

   public void setNote(String note) {
      this.note = note;
   }

   public String getAccessRuleName() {
      return this.accessRuleName;
   }

   public void setAccessRuleName(String accessRuleName) {
      this.accessRuleName = accessRuleName;
   }

   public CredentialCreateDto getCredential() {
      return this.credential;
   }

   public void setCredential(CredentialCreateDto credential) {
      this.credential = credential;
   }

   public List<BannerCreateDto> getBanners() {
      return this.banners;
   }

   public void setBanners(List<BannerCreateDto> banners) {
      this.banners = banners;
   }

   public List<SessionInputConstraintViolationHandlerCreateDto> getSessionInputConstraints() {
      return this.sessionInputConstraints;
   }

   public void setSessionInputConstraints(List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints) {
      this.sessionInputConstraints = sessionInputConstraints;
   }

   public AccessibilityTimePeriodConstraintCreateDto getAccessibilityTimePeriodConstraint() {
      return this.accessibilityTimePeriodConstraint;
   }

   public void setAccessibilityTimePeriodConstraint(AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint) {
      this.accessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint;
   }
}
