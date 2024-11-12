package ir.fidar.pam.service.connection;

import ir.fidar.core.service.generic.GenericService;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.dto.credential.create.CredentialCreateDto;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import java.util.List;
import java.util.Set;

public interface ConnectionService extends GenericService<Connection, String> {
   Connection getOne(String var1, boolean var2);

   void createNewRecord(
      String var1,
      ConnectionType var2,
      String var3,
      int var4,
      boolean var5,
      FileTransferMode var6,
      CredentialCreateDto var7,
      List<BannerCreateDto> var8,
      List<SessionInputConstraintViolationHandlerCreateDto> var9,
      AccessibilityTimePeriodConstraintCreateDto var10
   ) throws Exception;

   String hasUserAlreadyAccessedToHost(long var1, String var3, int var4, ConnectionType var5);

   Connection getOneByHostInfo(ConnectionType var1, String var2, int var3, boolean var4);

   Set<String> getAllConnectionsThatCurrentUserCanReviewTheirCaptures();

   Connection getOneByTransparentPort(int var1);

   ConnectionInfoDto convertToInfoDto(Connection var1);

   FileTransferMode resolveFileTransferMode(Connection var1);

   boolean resolveBastionStatus(Connection var1);

   Set<Connection> getAllByAccessRuleId(long var1);

   Credential getTypedCredential(Credential var1);
}
