package ir.fidar.pam.domain.dto.connection.create;

import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.type.FileTransferMode;

public class FileTransferSupportConnectionCreateDto extends ConnectionUpdateDto {
   private FileTransferMode fileTransferMode = FileTransferMode.NONE;
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
