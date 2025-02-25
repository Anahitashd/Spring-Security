package ir.fidar.pam.service.impl;

import ir.fidar.pam.da.repository.CaptureTransferredClipboardRepository;
import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import ir.fidar.pam.service.CaptureTransferredClipboardService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CaptureTransferredClipboardServiceImpl implements CaptureTransferredClipboardService {
   private final CaptureTransferredClipboardRepository captureTransferredClipboardRepository;

   public CaptureTransferredClipboardServiceImpl(CaptureTransferredClipboardRepository captureTransferredClipboardRepository) {
      this.captureTransferredClipboardRepository = captureTransferredClipboardRepository;
   }

   @Transactional(
      readOnly = true,
      propagation = Propagation.SUPPORTS
   )
   @Override
   public Page<CaptureTransferredClipboard> getAllBySpecificCapture(Long captureId, Pageable pageable) {
      return this.captureTransferredClipboardRepository
         .findAllByCaptureId(captureId, PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), Sort.by(new Order[]{Order.desc("id")})));
   }

   @Transactional
   @Override
   public void create(CaptureTransferredClipboard captureTransferredClipboard) {
      if (captureTransferredClipboard != null) {
         this.captureTransferredClipboardRepository.save(captureTransferredClipboard);
      }
   }
}
