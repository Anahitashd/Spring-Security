package ir.fidar.pam.domain.type;

public enum ExcelImportSection {
   USER("users.xlsx"),
   USER_GROUP("user-groups.xlsx"),
   SESSION_INPUT_CONSTRAINT("session-input-constraints.xlsx"),
   CONNECTION("connections.xlsx");

   private final String templateFileName;

   private ExcelImportSection(String templateFileName) {
      this.templateFileName = templateFileName;
   }

   public String getTemplateFileName() {
      return this.templateFileName;
   }
}
