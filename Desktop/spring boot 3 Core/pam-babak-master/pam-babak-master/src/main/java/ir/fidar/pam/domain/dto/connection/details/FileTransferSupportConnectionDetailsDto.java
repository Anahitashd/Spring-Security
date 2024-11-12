package ir.fidar.pam.domain.dto.connection.details;

import ir.fidar.pam.domain.type.FileTransferMode;

public class FileTransferSupportConnectionDetailsDto extends ConnectionDetailsDto {
   private FileTransferMode fileTransferMode;
   private boolean malwareScanningEnabled;

   @Override
   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   @Override
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
