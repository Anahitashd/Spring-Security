package ir.fidar.pam.domain.type;

public enum ExcelExportSection {
   USER("users"),
   ACCESS_RULE("access-rules"),
   SESSION_INPUT_CONSTRAINT("session-input-constraints"),
   CONNECTION("connections");

   private final String exportFinalName;

   private ExcelExportSection(String exportFinalName) {
      this.exportFinalName = exportFinalName;
   }

   public String getExportFinalName() {
      return this.exportFinalName;
   }
}
