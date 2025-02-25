package ir.fidar.pam.service.report;

import ir.fidar.pam.domain.dto.report.useractivity.UserAuthenticationAttemptCountDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserConstraintViolationsOverRemoteSessionDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserRemoteSessionDurationDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserSessionCountPerTypeDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserTransferredFilesOverRemoteSessionDto;
import ir.fidar.pam.domain.type.TimeUnit;
import java.util.List;

public interface UserActivityReportService {
   List<UserAuthenticationAttemptCountDto> retrieveAuthenticationAttemptsInLastUnitTime(TimeUnit var1, int var2);

   List<UserAuthenticationAttemptCountDto> retrieveAuthenticationAttemptsInLastUnitTime(String var1, TimeUnit var2, int var3);

   UserAuthenticationAttemptCountDto retrieveTotalAuthenticationAttempts(String var1);

   UserSessionCountPerTypeDto retrieveSessionCountsPerType(String var1);

   List<UserSessionCountPerTypeDto> retrieveSessionCountsPerTypeBaseOnTime(String var1, TimeUnit var2, int var3);

   List<UserTransferredFilesOverRemoteSessionDto> retrieveUserTransferredFilesOverRemoteSessions(String var1);

   List<UserConstraintViolationsOverRemoteSessionDto> retrieveUserConstraintViolationsOverRemoteSessions(String var1);

   List<UserRemoteSessionDurationDto> retrieveLastNRemoteSessionDuration(int var1);

   List<UserRemoteSessionDurationDto> retrieveUserLastNRemoteSessionDuration(String var1, int var2);
}
