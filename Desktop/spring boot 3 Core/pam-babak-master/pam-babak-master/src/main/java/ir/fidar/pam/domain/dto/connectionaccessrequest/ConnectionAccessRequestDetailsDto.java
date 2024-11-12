package ir.fidar.pam.domain.dto.connectionaccessrequest;

import ir.fidar.core.domain.dto.crud.DetailsDto;

public class ConnectionAccessRequestDetailsDto extends ConnectionAccessRequestListDto implements DetailsDto {
   private String adminReviewNote;
   private String description;

   public String getAdminReviewNote() {
      return this.adminReviewNote;
   }

   public void setAdminReviewNote(String adminReviewNote) {
      this.adminReviewNote = adminReviewNote;
   }

   public String getDescription() {
      return this.description;
   }

   public void setDescription(String description) {
      this.description = description;
   }
}
