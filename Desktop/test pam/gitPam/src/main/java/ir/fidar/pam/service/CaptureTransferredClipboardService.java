package ir.fidar.pam.service;

import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CaptureTransferredClipboardService {
   Page<CaptureTransferredClipboard> getAllBySpecificCapture(Long var1, Pageable var2);

   void create(CaptureTransferredClipboard var1);
}
