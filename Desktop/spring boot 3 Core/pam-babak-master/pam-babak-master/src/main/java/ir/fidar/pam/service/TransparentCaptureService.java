package ir.fidar.pam.service;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.domain.dto.capture.TransparentCaptureRegistrationDto;
import ir.fidar.pam.domain.dto.connection.TransparentConnectionPortMappingDto;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import java.util.List;
import java.util.Optional;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.domain.Pageable;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

public interface TransparentCaptureService {
   Optional<List<? extends ListDto>> load(List<LinkedFilter> var1, Sorting var2);

   Optional<CustomPageDto<? extends ListDto>> load(List<LinkedFilter> var1, Pageable var2, Sorting var3) throws Exception;

   String registerNewSession(TransparentCaptureRegistrationDto var1, String var2);

   void closeSession(String var1, String var2);

   TransparentConnectionPortMappingDto loadConnectionMappedToPort(int var1, String var2);

   String generateDownloadIdentifier(String var1) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;

   FileSystemResource playVideo(String var1, String var2, String var3) throws FileNotFoundException, NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;

   StreamingResponseBody downloadVideo(String var1, HttpServletResponse var2) throws FileNotFoundException, NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException;
}
