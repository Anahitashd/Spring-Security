package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.security.context.ApplicationStartupInitializer;
import ir.fidar.core.util.TemporalUtils;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.da.repository.SessionScanningTransferredFileRepository;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.SessionScanningTransferredFile;
import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.KavoshIntegrationService;
import ir.fidar.pam.service.SessionScanningTransferredFileService;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionScanningTransferredFileServiceImpl implements SessionScanningTransferredFileService, ApplicationStartupInitializer {
   private static final Logger LOGGER = LogManager.getLogger();
   private final SessionScanningTransferredFileRepository sessionScanningTransferredFileRepository;
   private final GenericCrudRepository<SessionScanningTransferredFile> crudRepository;
   private final NativeQueryBasedReadRepository<SessionScanningTransferredFile> readRepository;
   private final KavoshIntegrationService kavoshIntegrationService;
   private final AsyncTaskExecutor asyncTaskExecutor;

   public SessionScanningTransferredFileServiceImpl(
      SessionScanningTransferredFileRepository sessionScanningTransferredFileRepository,
      GenericCrudRepository<SessionScanningTransferredFile> crudRepository,
      NativeQueryBasedReadRepository<SessionScanningTransferredFile> readRepository,
      KavoshIntegrationService kavoshIntegrationService,
      AsyncTaskExecutor asyncTaskExecutor
   ) {
      this.crudRepository = crudRepository;
      this.readRepository = readRepository;
      this.sessionScanningTransferredFileRepository = sessionScanningTransferredFileRepository;
      this.kavoshIntegrationService = kavoshIntegrationService;
      this.asyncTaskExecutor = asyncTaskExecutor;
   }

   @Override
   public void initialize() throws Exception {
      File storageDir = new File(this.kavoshIntegrationService.getTempStoragePath());
      if (!storageDir.exists()) {
         storageDir.mkdir();
      } else {
         String[] files = storageDir.list();

         for (String file : files) {
            Files.delete(Paths.get(this.getStoragePath(file).toString()));
         }
      }

      this.sessionScanningTransferredFileRepository.deleteAll();
      this.asyncTaskExecutor.executeTask(() -> {
         List<SessionScanningTransferredFile> sessionScanningTransferredFiles = this.sessionScanningTransferredFileRepository.findAll();
         List<SessionScanningTransferredFile> removingRecords = new ArrayList<>();

         for (SessionScanningTransferredFile sessionScanningTransferredFile : sessionScanningTransferredFiles) {
            if (Instant.now().getEpochSecond() - sessionScanningTransferredFile.getRegistrationTime() > (long)TemporalUtils.hoursToSeconds(6)) {
               removingRecords.add(sessionScanningTransferredFile);
            }
         }

         this.sessionScanningTransferredFileRepository.deleteAll(removingRecords);
      }, 8, 8, TimeUnit.HOURS);
   }

   @Transactional
   @Override
   public SessionScanningTransferredFile registerNewFile(Capture capture, String fileName) {
      String uuid;
      do {
         uuid = UUID.randomUUID().toString();
      } while (this.existsByUuid(uuid));

      SessionScanningTransferredFile sessionScanningTransferredFile = new SessionScanningTransferredFile();
      sessionScanningTransferredFile.setCapture(capture);
      sessionScanningTransferredFile.setUuid(uuid);
      sessionScanningTransferredFile.setFileName(fileName);
      sessionScanningTransferredFile.setRegistrationTime(Instant.now().getEpochSecond());
      this.sessionScanningTransferredFileRepository.save(sessionScanningTransferredFile);
      return sessionScanningTransferredFile;
   }

   @Override
   public SessionScanningTransferredFile getByUuid(String uuid) {
      return this.sessionScanningTransferredFileRepository.findOneByUuid(uuid);
   }

   @Transactional
   @Override
   public void registerFileForScanning(String uuid) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      SessionScanningTransferredFile sessionScanningTransferredFile = Optional.ofNullable(this.sessionScanningTransferredFileRepository.findOneByUuid(uuid))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionScanningTransferredFile.class)));
      String requestUuid = this.kavoshIntegrationService.sendFile(this.getStoragePath(uuid).toFile(), sessionScanningTransferredFile.getFileName());
      LOGGER.debug(
         Markers.SESSION,
         "File '{}' on connection '{}' in remote-session '{}' is sent to Kavosh for malware scanning",
         sessionScanningTransferredFile.getFileName(),
         SessionServiceImpl.generateConnectionInfoForLogging(sessionScanningTransferredFile.getCapture()),
         sessionScanningTransferredFile.getCapture().getSessionId()
      );
      sessionScanningTransferredFile.setKavoshRequestIdentifier(requestUuid);
   }

   @Override
   public KavoshIntegrationService.FileStatus checkStatus(String uuid) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      SessionScanningTransferredFile sessionScanningTransferredFile = this.getByUuid(uuid);
      return this.kavoshIntegrationService.getStatus(sessionScanningTransferredFile.getKavoshRequestIdentifier());
   }

   @Override
   public SessionScanningTransferredFile delete(String uuid) {
      SessionScanningTransferredFile sessionScanningTransferredFile = this.getByUuid(uuid);
      RepositoryContextManager.startNewTransaction();

      try {
         this.crudRepository.remove(sessionScanningTransferredFile);
         Files.deleteIfExists(this.getStoragePath(uuid));
      } catch (IOException var4) {
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }

      return sessionScanningTransferredFile;
   }

   @Override
   public Path getStoragePath(String uuid) {
      return this.existsByUuid(uuid) ? Paths.get(this.kavoshIntegrationService.getTempStoragePath()).resolve(uuid) : null;
   }

   private boolean existsByUuid(String uuid) {
      return this.sessionScanningTransferredFileRepository.existsByUuid(uuid);
   }

   private SessionScanningTransferredFile getOneByUuid(String uuid, boolean readOnly) {
      return this.readRepository
         .findOne(
            new NativeQueryBuilder()
               .from(SessionScanningTransferredFile.class, "sstf")
               .where(QueryAndFilterUtils.caseInsensitiveStringFilter("uuid", uuid))
               .build(),
            readOnly
         );
   }
}
