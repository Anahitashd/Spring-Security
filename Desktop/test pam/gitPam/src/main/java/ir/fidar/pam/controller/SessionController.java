package ir.fidar.pam.controller;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.annotation.Pagination;
import ir.fidar.core.domain.annotation.Sort;
import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.SessionService;
import java.util.Set;
import javax.validation.constraints.NotBlank;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping({"/api/sessions"})
public class SessionController {
   private final AccessRuleCrudService accessRuleCrudService;
   private final SessionService sessionService;

   public SessionController(
      @Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService, @Qualifier("remoteSessionService") SessionService sessionService
   ) {
      this.accessRuleCrudService = accessRuleCrudService;
      this.sessionService = sessionService;
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getSessionsOfCurrentUser(
      @Pagination Pageable pageable,
      @Sort(Capture.class) Sorting sorting,
      @RequestParam(name = "filter",required = false,defaultValue = "") String filter,
      @RequestParam(name = "types",required = false,defaultValue = "") Set<String> typesFilter
   ) {
      return ResponseEntity.ok(
         Response.success(
            "session.read", this.accessRuleCrudService.loadSessionsOfCurrentUser(pageable, sorting, filter, typesFilter).orElse(PagingUtil.emptyCustomPage())
         )
      );
   }

   @GetMapping({"/{sessionId}/terminate"})
   public ResponseEntity<Response> terminateSession(@PathVariable(name = "sessionId") String sessionId) throws Exception {
      this.sessionService.terminateLiveSession(sessionId);
      return ResponseEntity.ok(Response.success("session.terminated"));
   }

   @GetMapping(
      value = {"/{sessionId}/download-stream"},
      params = {"stream", "file"}
   )
   public ResponseEntity<StreamingResponseBody> downloadInterceptedStream(
      @PathVariable(name = "sessionId") String sessionId,
      @RequestParam(name = "stream") int streamIndex,
      @NotBlank @RequestParam(name = "file") String fileName
   ) throws Exception {
      return ResponseEntity.ok(this.sessionService.downloadStream(sessionId, streamIndex, fileName));
   }

   @PostMapping(
      consumes = {"*/*"},
      value = {"/{sessionId}/upload-stream"},
      params = {"stream", "file"}
   )
   public void uploadByInterceptingStream(
      @PathVariable(name = "sessionId") String sessionId,
      @RequestParam(name = "stream") int streamIndex,
      @NotBlank @RequestParam(name = "file") String fileName
   ) throws Exception {
      this.sessionService.uploadStream(sessionId, streamIndex, fileName);
   }

   @GetMapping({"/keep-alive"})
   public ResponseEntity<Response> keepUserLoggedIn() {
      return ResponseEntity.ok(Response.success("keep_alive.read"));
   }

   @GetMapping(
      path = {"/{sessionId}/requested-files/{uuid}"}
   )
   public StreamingResponseBody downloadScannedRequestedFile(@PathVariable(name = "sessionId") String sessionId, @PathVariable(name = "uuid") String fileUuid) throws FileNotFoundException, InsufficientPrivilegeToAccessSessionException {
      return this.sessionService.downloadRequestedFile(sessionId, fileUuid);
   }
}
