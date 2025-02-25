package ir.fidar.pam.domain.dto.connection;

import ir.fidar.pam.domain.type.FileTransferMode;

public class ConnectionSessionInteractionModeDto {
   private boolean clipboard;
   private FileTransferMode fileTransferMode;
   private boolean bastion;

   public boolean isClipboard() {
      return this.clipboard;
   }

   public void setClipboard(boolean clipboard) {
      this.clipboard = clipboard;
   }

   public FileTransferMode getFileTransferMode() {
      return this.fileTransferMode;
   }

   public void setFileTransferMode(FileTransferMode fileTransferMode) {
      this.fileTransferMode = fileTransferMode;
   }

   public boolean isBastion() {
      return this.bastion;
   }

   public void setBastion(boolean bastion) {
      this.bastion = bastion;
   }
}
