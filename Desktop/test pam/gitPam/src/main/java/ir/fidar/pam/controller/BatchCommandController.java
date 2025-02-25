package ir.fidar.pam.controller;

import ir.fidar.core.management.response.Response;
import ir.fidar.pam.domain.dto.batchcommand.BatchCommandDto;
import ir.fidar.pam.service.BatchCommandService;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/batch-command-execution"})
public class BatchCommandController {
   private final BatchCommandService batchCommandService;

   public BatchCommandController(BatchCommandService batchCommandService) {
      this.batchCommandService = batchCommandService;
   }

   @PostMapping
   public ResponseEntity<Response> executeCommandsInSpecifiedConnections(@RequestBody List<BatchCommandDto> batchCommandDtoList) throws AccessDeniedException, InterruptedException {
      return ResponseEntity.ok(Response.success("batch_cmd.executed", this.batchCommandService.executeCommands(batchCommandDtoList)));
   }
}
