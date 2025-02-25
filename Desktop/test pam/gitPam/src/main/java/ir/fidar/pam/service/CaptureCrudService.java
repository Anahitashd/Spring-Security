package ir.fidar.pam.service;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.exception.CaptureExecutedCommandNotSupportedException;
import ir.fidar.pam.exception.TransferredFileNotFound;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import reactor.core.publisher.Flux;

public interface CaptureCrudService {
   Optional<List<ListDto>> load(List<LinkedFilter> var1, Sorting var2);

   Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> var1, Pageable var2, Sorting var3) throws Exception;

   Optional<DetailsDto> load(String var1) throws Exception;

   StreamingResponseBody downloadRecordFile(String var1) throws Exception;

   StreamingResponseBody convertToVideo(String var1, String var2, int var3) throws Exception;

   Optional<List<String>> loadImages(String var1) throws Exception;

   Optional<List<String>> loadImages(String var1, String var2) throws Exception;

   void downloadTransferredFile(String var1, String var2) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, TransferredFileNotFound, IOException;

   void checkIntegrity(String var1) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, InterruptedException;

   Optional<List<ListDto>> loadTransferredFiles(String var1) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;

   Optional<List<ListDto>> loadInputConstraintViolations(String var1) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;

   Optional<CustomPageDto<? extends ListDto>> loadTransferredClipboards(String var1, Pageable var2) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;

   Optional<CustomPageDto<? extends ListDto>> loadExecutedCommands(String var1, Pageable var2) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, CaptureExecutedCommandNotSupportedException;

   Optional<Flux<? extends ListDto>> streamKeyEvents(String var1) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, FileNotFoundException;
}
