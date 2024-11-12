package ir.fidar.pam.service;

import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import java.io.File;

public interface KavoshIntegrationService {
   void validateIntegration() throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   String getTempStoragePath();

   String sendFile(File var1) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   String sendFile(File var1, String var2) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   KavoshIntegrationService.FileStatus getStatus(String var1) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException;

   public static enum FileStatus {
      CLEAN,
      INFECTED,
      SCANNING;
   }
}
