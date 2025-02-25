package ir.fidar.pam.domain.dto.connectionaccessrequest;

public class ConnectionAccessRequestReviewDetailsDto extends ConnectionAccessRequestDetailsDto {
   private String applicant;

   public String getApplicant() {
      return this.applicant;
   }

   public void setApplicant(String applicant) {
      this.applicant = applicant;
   }
}
