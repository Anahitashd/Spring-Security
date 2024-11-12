package ir.fidar.pam.domain.dto.accessrule;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.pam.domain.type.FileTransferMode;

public class AccessRuleListDto extends FullAuditionReadDto {
   private String name;
   private int numberOfUsers;
   private boolean clipboard;
   private FileTransferMode fileTransferMode;
   private boolean disabled;
   private long expirationTime;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public int getNumberOfUsers() {
      return this.numberOfUsers;
   }

   public void setNumberOfUsers(int numberOfUsers) {
      this.numberOfUsers = numberOfUsers;
   }

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

   public boolean isDisabled() {
      return this.disabled;
   }

   public void setDisabled(boolean disabled) {
      this.disabled = disabled;
   }

   public long getExpirationTime() {
      return this.expirationTime;
   }

   public void setExpirationTime(long expirationTime) {
      this.expirationTime = expirationTime;
   }
}
