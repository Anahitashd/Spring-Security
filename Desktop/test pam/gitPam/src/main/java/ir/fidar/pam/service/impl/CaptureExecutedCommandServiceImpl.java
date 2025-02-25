package ir.fidar.pam.service.impl;

import ir.fidar.pam.da.repository.CaptureExecutedCommandRepository;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.service.CaptureExecutedCommandService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CaptureExecutedCommandServiceImpl implements CaptureExecutedCommandService {
   private final CaptureExecutedCommandRepository captureExecutedCommandRepository;

   public CaptureExecutedCommandServiceImpl(CaptureExecutedCommandRepository captureExecutedCommandRepository) {
      this.captureExecutedCommandRepository = captureExecutedCommandRepository;
   }

   @Transactional(
      readOnly = true,
      propagation = Propagation.SUPPORTS
   )
   @Override
   public Page<CaptureExecutedCommand> getAllBySpecificCapture(Long captureId, Pageable pageable) {
      return this.captureExecutedCommandRepository
         .findAllByCaptureId(captureId, PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), Sort.by(new Order[]{Order.desc("id")})));
   }

   @Transactional
   @Override
   public void create(CaptureExecutedCommand captureTransferredClipboard) {
      if (captureTransferredClipboard != null) {
         this.captureExecutedCommandRepository.save(captureTransferredClipboard);
      }
   }
}
