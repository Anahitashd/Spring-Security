package ir.fidar.pam.service.connection;

import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.capturerule.CaptureRulePrivilegesDto;
import ir.fidar.pam.domain.dto.connection.ConnectionServicesDto;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationDetailsDto;
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.dto.credential.details.CredentialDetailsDto;
import ir.fidar.pam.exception.connection.RemoteApplicationOnlySupportedByRdpConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import java.util.List;
import java.util.Optional;

public interface ConnectionCrudService extends CrudService<String, ConnectionCreateDto, ConnectionUpdateDto> {
   Optional<List<CredentialDetailsDto>> loadCredentialsOfSpecificConnection(String var1);

   Optional<ConnectionServicesDto> loadServicesOfSpecificConnection(String var1);

   Optional<CaptureRulePrivilegesDto> loadCapturePrivilegesOfCurrentUserOnSpecificConnection(String var1) throws InsufficientPrivilegeToAccessCaptureException;

   Optional<List<RdpConnectionRemoteApplicationDetailsDto>> loadRemoteApplicationsOfSpecificConnection(String var1) throws RemoteApplicationOnlySupportedByRdpConnectionException;
}
