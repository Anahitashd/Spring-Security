package ir.fidar.pam.service;

import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface CaptureExecutedCommandService {
   Page<CaptureExecutedCommand> getAllBySpecificCapture(Long var1, Pageable var2);

   void create(CaptureExecutedCommand var1);
}
