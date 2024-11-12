package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.pam.domain.type.CaptureTransferredClipboardSource;

public class CaptureTransferredClipboardListDto implements ListDto {
   private String content;
   private long time;
   private int elapsedTime;
   private CaptureTransferredClipboardSource source;

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

   public int getElapsedTime() {
      return this.elapsedTime;
   }

   public void setElapsedTime(int elapsedTime) {
      this.elapsedTime = elapsedTime;
   }

   public CaptureTransferredClipboardSource getSource() {
      return this.source;
   }

   public void setSource(CaptureTransferredClipboardSource source) {
      this.source = source;
   }
}
