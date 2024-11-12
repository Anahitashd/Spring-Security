package ir.fidar.pam.domain.dto.report.useractivity;

public class UserAuthenticationAttemptCountDto {
   private int successfulAttempts;
   private int failedAttempts;
   private int time;

   public int getSuccessfulAttempts() {
      return this.successfulAttempts;
   }

   public void setSuccessfulAttempts(int successfulAttempts) {
      this.successfulAttempts = successfulAttempts;
   }

   public int getFailedAttempts() {
      return this.failedAttempts;
   }

   public void setFailedAttempts(int failedAttempts) {
      this.failedAttempts = failedAttempts;
   }

   public int getTime() {
      return this.time;
   }

   public void setTime(int time) {
      this.time = time;
   }
}
