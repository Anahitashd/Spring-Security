package ir.fidar.pam.service;

import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.SessionScanningTransferredFile;
import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import java.nio.file.Path;

public interface SessionScanningTransferredFileService {
   SessionScanningTransferredFile registerNewFile(Capture var1, String var2);

   SessionScanningTransferredFile getByUuid(String var1);

   void registerFileForScanning(String var1) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   KavoshIntegrationService.FileStatus checkStatus(String var1) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   SessionScanningTransferredFile delete(String var1);

   Path getStoragePath(String var1);
}
