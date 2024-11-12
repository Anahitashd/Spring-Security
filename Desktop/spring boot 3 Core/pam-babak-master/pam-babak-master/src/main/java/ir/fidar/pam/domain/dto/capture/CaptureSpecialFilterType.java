package ir.fidar.pam.domain.dto.capture;

import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.model.session.SessionTransferredFile;

public enum CaptureSpecialFilterType {
   TRANSFERRED_FILE("transferred-file.", "name", SessionTransferredFile.class),
   INPUT_CONSTRAINT_VIOLATION("input-const.", "input", SessionInputConstraintViolationIncident.class),
   EXECUTED_COMMAND("exec-cmd.", "content", CaptureExecutedCommand.class);

   private final String filterProperty;
   private final String targetField;
   private final Class<?> targetEntity;

   private CaptureSpecialFilterType(String filterProperty, String targetField, Class<?> targetEntity) {
      this.filterProperty = filterProperty;
      this.targetField = targetField;
      this.targetEntity = targetEntity;
   }

   public String getFilterProperty() {
      return this.filterProperty;
   }

   public String getTargetField() {
      return this.targetField;
   }

   public Class<?> getTargetEntity() {
      return this.targetEntity;
   }
}
