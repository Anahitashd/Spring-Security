package ir.fidar.pam.domain.dto.connectionaccessrequest;

public class ConnectionAccessRequestReviewListDto extends ConnectionAccessRequestListDto {
   private String applicant;

   public String getApplicant() {
      return this.applicant;
   }

   public void setApplicant(String applicant) {
      this.applicant = applicant;
   }
}
