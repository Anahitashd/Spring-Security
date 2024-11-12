package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.ListDto;

public class CaptureExecutedCommandListDto implements ListDto {
   private String content;
   private long time;
   private long elapsedTime;

   public String getContent() {
      return this.content;
   }

   public void setContent(String content) {
      this.content = content;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }

   public long getElapsedTime() {
      return this.elapsedTime;
   }

   public void setElapsedTime(long elapsedTime) {
      this.elapsedTime = elapsedTime;
   }
}
