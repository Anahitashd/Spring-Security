package ir.fidar.pam.service;

import ir.fidar.pam.domain.dto.batchcommand.BatchCommandDto;
import ir.fidar.pam.domain.dto.batchcommand.BatchCommandResultDto;
import java.util.List;

public interface BatchCommandService {
   List<BatchCommandResultDto> executeCommands(List<BatchCommandDto> var1) throws InterruptedException;
}
