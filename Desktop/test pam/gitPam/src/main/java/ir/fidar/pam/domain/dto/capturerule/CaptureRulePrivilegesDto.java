package ir.fidar.pam.domain.dto.capturerule;

public class CaptureRulePrivilegesDto {
   private boolean export;
   private boolean keystroke;

   public boolean isExport() {
      return this.export;
   }

   public void setExport(boolean export) {
      this.export = export;
   }

   public boolean isKeystroke() {
      return this.keystroke;
   }

   public void setKeystroke(boolean keystroke) {
      this.keystroke = keystroke;
   }
}
