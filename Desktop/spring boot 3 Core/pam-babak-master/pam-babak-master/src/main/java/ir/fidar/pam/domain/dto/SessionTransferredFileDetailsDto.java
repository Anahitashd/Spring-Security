package ir.fidar.pam.domain.dto;

import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.pam.domain.type.SessionTransferFileMode;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;

public class SessionTransferredFileDetailsDto implements ListDto, DetailsDto {
   private String name;
   private long time;
   private SessionTransferFileMode mode;
   private SessionTransferredFileStatus status;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public SessionTransferFileMode getMode() {
      return this.mode;
   }

   public void setMode(SessionTransferFileMode mode) {
      this.mode = mode;
   }

   public SessionTransferredFileStatus getStatus() {
      return this.status;
   }

   public void setStatus(SessionTransferredFileStatus status) {
      this.status = status;
   }
}
