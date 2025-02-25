package ir.fidar.pam.controller;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.annotation.Pagination;
import ir.fidar.core.domain.annotation.Sort;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.util.constraint.UniquePropertyProvided;
import ir.fidar.core.domain.util.constraint.Uuid;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.core.util.filter.web.resolver.Filter;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.service.CaptureCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import reactor.core.publisher.Flux;

@RestController
@RequestMapping({"/api/captures"})
public class CaptureController {
   private final CaptureCrudService captureCrudService;

   public CaptureController(@Qualifier("captureCrudServiceImpl") CaptureCrudService captureCrudService) {
      this.captureCrudService = captureCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllCaptures(@Filter(Capture.class) List<LinkedFilter> filters, @Sort(Capture.class) Sorting sorting) {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllCaptures(
      @Filter(Capture.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(Capture.class) Sorting sorting
   ) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @GetMapping({"/{sessionId}"})
   public ResponseEntity<Response> getOneRecordByUniqueIdentifier(@Uuid @PathVariable(name = "sessionId") @UniquePropertyProvided String sessionId) throws Throwable {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.load(sessionId).get()));
   }

   @GetMapping({"/{sessionId}/record-file"})
   public ResponseEntity<StreamingResponseBody> getRecordFileOfSpecificSession(@Uuid @PathVariable(name = "sessionId") @UniquePropertyProvided String sessionId) throws Throwable {
      return ResponseEntity.ok(this.captureCrudService.downloadRecordFile(sessionId));
   }

   @GetMapping(
      value = {"/{sessionId}/convert-to-video"},
      params = {"file-name", "bitrate"}
   )
   public ResponseEntity<StreamingResponseBody> convertSpecificCaptureToVideo(
      @Uuid @PathVariable(name = "sessionId") String sessionId, @RequestParam(name = "file-name") String fileName, @RequestParam(name = "bitrate") int bitrate
   ) throws Exception {
      return ResponseEntity.ok(this.captureCrudService.convertToVideo(sessionId, fileName, bitrate));
   }

   @GetMapping({"/{sessionId}/images"})
   public ResponseEntity<Response> getImagesOfSpecificCapture(@Uuid @PathVariable(name = "sessionId") String sessionId) throws Exception {
      return ResponseEntity.ok(Response.success("capture.images.read", this.captureCrudService.loadImages(sessionId).get()));
   }

   @GetMapping(
      value = {"/{sessionId}/images"},
      params = {"search-query"}
   )
   public ResponseEntity<Response> getImagesOfSpecificCaptureBySearch(
      @Uuid @PathVariable(name = "sessionId") String sessionId, @RequestParam(name = "search-query") String search
   ) throws Exception {
      return ResponseEntity.ok(Response.success("capture.images.read", this.captureCrudService.loadImages(sessionId, search).get()));
   }

   @GetMapping({"/{sessionId}/transferred-files/{fileName}"})
   public ResponseEntity<Response> downloadTransferredFile(
      @Uuid @PathVariable(name = "sessionId") String sessionId, @PathVariable(name = "fileName") String fileName
   ) throws Exception {
      this.captureCrudService.downloadTransferredFile(sessionId, fileName);
      return ResponseEntity.ok(Response.success("capture.transferred_file.read"));
   }

   @GetMapping({"/{sessionId}/check-integrity"})
   public ResponseEntity<Response> checkCaptureFileIntegrity(@Uuid @PathVariable(name = "sessionId") String sessionId) throws Exception {
      this.captureCrudService.checkIntegrity(sessionId);
      return ResponseEntity.ok(Response.success("capture.file_integrity.checked"));
   }

   @GetMapping(
      path = {"/{sessionId}/transferred-files"}
   )
   public ResponseEntity<Response> getTransferredFilesOfSpecificSession(@Uuid @PathVariable(name = "sessionId") String sessionId) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.loadTransferredFiles(sessionId)));
   }

   @GetMapping(
      path = {"/{sessionId}/input-constraint-violations"}
   )
   public ResponseEntity<Response> getInputConstraintViolationsOfSpecificSession(@Uuid @PathVariable(name = "sessionId") String sessionId) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.loadInputConstraintViolations(sessionId)));
   }

   @GetMapping(
      path = {"/{sessionId}/key-events"}
   )
   public ResponseEntity<Flux<? extends ListDto>> getKeyInputsOfSpecificSession(@Uuid @PathVariable(name = "sessionId") String sessionId) throws Exception {
      return ResponseEntity.ok(this.captureCrudService.streamKeyEvents(sessionId).orElse(Flux.empty()));
   }

   @GetMapping(
      path = {"/{sessionId}/transferred-clipboards"},
      params = {"page"}
   )
   public ResponseEntity<Response> getTransferredClipboardsOfSpecificSession(
      @Uuid @PathVariable(name = "sessionId") String sessionId, @Pagination Pageable pageable
   ) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.loadTransferredClipboards(sessionId, pageable)));
   }

   @GetMapping(
      path = {"/{sessionId}/executed-commands"},
      params = {"page"}
   )
   public ResponseEntity<Response> getExecutedCommandsOfSpecificSession(@Uuid @PathVariable(name = "sessionId") String sessionId, @Pagination Pageable pageable) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.captureCrudService.loadExecutedCommands(sessionId, pageable)));
   }
}
