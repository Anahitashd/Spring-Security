package ir.fidar.pam.session.inputextraction.writer;

import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import ir.fidar.pam.domain.type.CaptureTransferredClipboardSource;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.inputextraction.model.ClipboardInfo;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import java.io.IOException;
import java.time.Instant;

public class ClipboardInputWriter implements ExtractedInputWriter<ClipboardInfo> {
   private final CaptureService captureService;
   private final ManagedSession managedSession;

   public ClipboardInputWriter(CaptureService captureService, ManagedSession managedSession) {
      this.captureService = captureService;
      this.managedSession = managedSession;
   }

   public void write(ClipboardInfo clipboardInfo) throws IOException {
      String content = clipboardInfo.getContent();
      if (StringUtils.hasContent(content)) {
         CaptureTransferredClipboard captureTransferredClipboard = new CaptureTransferredClipboard();
         captureTransferredClipboard.setContent(content);
         captureTransferredClipboard.setElapsedTime(clipboardInfo.getTime());
         captureTransferredClipboard.setTime(Instant.now().getEpochSecond());
         captureTransferredClipboard.setSource(
            clipboardInfo.getSource().equals(InputSource.SERVER) ? CaptureTransferredClipboardSource.SERVER : CaptureTransferredClipboardSource.CLIENT
         );
         this.captureService.addTransferredClipboard(this.managedSession.getId(), captureTransferredClipboard);
      }
   }

   @Override
   public void close() throws IOException {
   }
}
