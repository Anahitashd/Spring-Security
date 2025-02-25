package ir.fidar.pam.domain.model.connection;

import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import javax.persistence.Convert;
import javax.persistence.MappedSuperclass;
import javax.validation.constraints.NotNull;

@MappedSuperclass
public class FileTransferSupportConnection {
   @NotNull(
      message = "null.fileTransferMode"
   )
   @Convert(
      converter = FileTransferModeConverter.class
   )
   private FileTransferMode fileTransferMode;
   private boolean malwareScanningEnabled;

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public boolean isMalwareScanningEnabled() {
      return this.malwareScanningEnabled;
   }

   public void setMalwareScanningEnabled(boolean malwareScanningEnabled) {
      this.malwareScanningEnabled = malwareScanningEnabled;
   }
}
