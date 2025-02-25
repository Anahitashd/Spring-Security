package ir.fidar.pam.controller;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.annotation.Pagination;
import ir.fidar.core.domain.annotation.Sort;
import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.util.HttpMimeType;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.core.util.filter.web.resolver.Filter;
import ir.fidar.pam.domain.dto.capture.TransparentCaptureRegistrationDto;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.service.TransparentCaptureService;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseEntity.BodyBuilder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping(
   path = {"/api/transparent-captures"}
)
@Validated
public class TransparentCaptureController {
   private final TransparentCaptureService transparentCaptureService;

   public TransparentCaptureController(TransparentCaptureService transparentCaptureService) {
      this.transparentCaptureService = transparentCaptureService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllCaptures(
      @Filter(Capture.class) List<LinkedFilter> filters, @Sort(value = Capture.class,toSnakeCase = false) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.transparentCaptureService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllCaptures(
      @Filter(Capture.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(value = Capture.class,toSnakeCase = false) Sorting sorting
   ) throws Exception {
      return ResponseEntity.ok(Response.Crud.get(this.transparentCaptureService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @PostMapping
   public ResponseEntity<Response> registerNewTransparentSession(
      @RequestBody @Valid TransparentCaptureRegistrationDto transparentCaptureRegistrationDto, @RequestParam(name = "token") String token
   ) {
      String uuid = this.transparentCaptureService.registerNewSession(transparentCaptureRegistrationDto, token);
      return ResponseEntity.ok(Response.success("trans_session.registered", uuid));
   }

   @PutMapping(
      path = {"/{sessionId}/close"}
   )
   public ResponseEntity<Response> closeTransparentSession(
      @NotBlank(message = "blank.sessionId") @PathVariable(name = "sessionId") String sessionId, @RequestParam(name = "token") String token
   ) {
      this.transparentCaptureService.closeSession(sessionId, token);
      return ResponseEntity.ok(Response.success("trans_session.closed"));
   }

   @GetMapping(
      path = {"/connection-port-mapping/{port}"}
   )
   public ResponseEntity<Response> getAllTransparentConnections(@PathVariable(name = "port") int port, @RequestParam(name = "token") String token) {
      return ResponseEntity.ok(Response.Crud.get(this.transparentCaptureService.loadConnectionMappedToPort(port, token)));
   }

   @GetMapping(
      path = {"/{sessionId}/video-id"}
   )
   public ResponseEntity<Response> generateUniqueDownloadIdentifier(@PathVariable(name = "sessionId") String sessionId) throws FileNotFoundException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException, InsufficientPrivilegeToAccessCaptureException {
      return ResponseEntity.ok(Response.success("trans_capture.dl_id", this.transparentCaptureService.generateDownloadIdentifier(sessionId)));
   }

   @GetMapping(
      path = {"/{sessionId}/play-video"},
      params = {"un", "id"}
   )
   public ResponseEntity<FileSystemResource> downloadCaptureVideo(
      @NotBlank(message = "blank.sessionId") @PathVariable(name = "sessionId") String sessionId,
      @RequestParam(name = "un") String username,
      @RequestParam(name = "id") String id
   ) throws FileNotFoundException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException, InsufficientPrivilegeToAccessCaptureException {
      HttpHeaders responseHeaders = new HttpHeaders();
      responseHeaders.add("Content-Type", HttpMimeType.AUDIO_MP4.getValue());
      return ((BodyBuilder)ResponseEntity.ok().headers(responseHeaders)).body(this.transparentCaptureService.playVideo(sessionId, username, id));
   }

   @GetMapping(
      path = {"/{sessionId}/download-video"}
   )
   public ResponseEntity<StreamingResponseBody> downloadCaptureVideo(
      @NotBlank(message = "blank.sessionId") @PathVariable(name = "sessionId") String sessionId, HttpServletResponse httpServletResponse
   ) throws FileNotFoundException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException, InsufficientPrivilegeToAccessCaptureException {
      return ResponseEntity.ok(this.transparentCaptureService.downloadVideo(sessionId, httpServletResponse));
   }
}
