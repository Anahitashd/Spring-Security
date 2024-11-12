package ir.fidar.pam.controller.management;

class MostActiveUsersDto {
   private String username;
   private int sessionCount;

   public String getUsername() {
      return this.username;
   }

   public void setUsername(String username) {
      this.username = username;
   }

   public int getSessionCount() {
      return this.sessionCount;
   }

   public void setSessionCount(int sessionCount) {
      this.sessionCount = sessionCount;
   }
}
