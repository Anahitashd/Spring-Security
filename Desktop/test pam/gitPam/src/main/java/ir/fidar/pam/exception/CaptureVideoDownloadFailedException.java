package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class CaptureVideoDownloadFailedException extends AbstractException {
   @Override
   public String getCode() {
      return "capture.video_download.failed";
   }
}
