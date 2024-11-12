package ir.fidar.pam.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.domain.dto.management.notification.ServerEvent;
import ir.fidar.core.domain.dto.management.notification.ServerEventType;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.core.exception.SseConnectionBrokenException;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.SystemConstantsAndDefaults;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.management.internationalization.MessageResolver;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.security.service.AuthorizationService;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.util.FileUtils;
import ir.fidar.core.util.HttpMimeType;
import ir.fidar.core.util.WebUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.pam.da.repository.CaptureRepository;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.RdpConnection;
import ir.fidar.pam.domain.model.connection.SshConnection;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.SessionScanningTransferredFile;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.type.SessionTransferFileMode;
import ir.fidar.pam.domain.type.SessionTransferredFileStatus;
import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToTransferFileOnSessionException;
import ir.fidar.pam.exception.session.SessionNotExistsException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.KavoshIntegrationService;
import ir.fidar.pam.service.SessionScanningTransferredFileService;
import ir.fidar.pam.service.SessionService;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.Session;
import ir.fidar.pam.session.SessionManager;
import ir.fidar.pam.session.event.SessionFileTransferringEvent;
import ir.fidar.pam.session.tunnel.StreamInterceptorTunnel;
import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jakarta.persistence.Tuple;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.guacamole.GuacamoleException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@Service("remoteSessionService")
public class SessionServiceImpl implements SessionService, ApplicationEventPublisherAware {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String TRANSFERRED_STORAGE_PATH_PREFIX = "/captures/transferred-files";
   private static final int CHECKING_SCANNING_FILE_STATUS_INTERVAL_SECONDS = 5;
   private final CaptureRepository captureRepository;
   private final AuthorizationService authorizationService;
   private final NativeQueryBasedReadRepository nativeQueryBasedReadRepository;
   private final JpaQueryBasedReadRepository jpaQueryBasedReadRepository;
   private final ObjectMapper objectMapper;
   private final SessionScanningTransferredFileService sessionScanningTransferredFileService;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private final NotificationService notificationService;
   private final MessageResolver messageResolver;
   private final int maxKavoshResponseWaitTime;
   private ApplicationEventPublisher applicationEventPublisher;

   public SessionServiceImpl(
      CaptureRepository captureRepository,
      AuthorizationService authorizationService,
      NativeQueryBasedReadRepository nativeQueryBasedReadRepository,
      JpaQueryBasedReadRepository jpaQueryBasedReadRepository,
      ObjectMapper objectMapper,
      SessionScanningTransferredFileService sessionScanningTransferredFileService,
      AsyncTaskExecutor asyncTaskExecutor,
      NotificationService notificationService,
      MessageResolver messageResolver,
      @Value("${remote-session.kavosh-response-wait-time:10}") int maxKavoshResponseWaitTime
   ) {
      this.captureRepository = captureRepository;
      this.authorizationService = authorizationService;
      this.nativeQueryBasedReadRepository = nativeQueryBasedReadRepository;
      this.jpaQueryBasedReadRepository = jpaQueryBasedReadRepository;
      this.objectMapper = objectMapper;
      this.sessionScanningTransferredFileService = sessionScanningTransferredFileService;
      this.asyncTaskExecutor = asyncTaskExecutor;
      this.notificationService = notificationService;
      this.messageResolver = messageResolver;
      this.maxKavoshResponseWaitTime = maxKavoshResponseWaitTime;
   }

   public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
      this.applicationEventPublisher = applicationEventPublisher;
   }

   @Transactional
   @Override
   public void terminateLiveSession(String sessionId) throws CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException, InsufficientPrivilegeToAccessCaptureException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibilityToTerminateSession(capture);
      ManagedSession managedSession = (ManagedSession)SessionManager.getSession(sessionId);
      if (managedSession != null) {
         managedSession.getWebsocketHandler().setCloseStatus(WebsocketSessionCloseStatus.TERMINATED_BY_PRIVILEGED_USER);
      } else if (capture.getStatus().equals(CaptureStatus.LIVE) || capture.getEndTime() == 0L) {
         capture.setStatus(CaptureStatus.CLOSED);
         capture.setEndTime((long)Long.valueOf(Instant.now().getEpochSecond()).intValue());
      }

      LOGGER.info(
         Markers.SESSION,
         "Session '{}' to connection '{}' is terminated by user '{}'",
         sessionId,
         capture.getConnectionName(),
         this.authorizationService.getCurrentUserInfo().getUsername()
      );
   }

   @Override
   public StreamingResponseBody downloadStream(String sessionId, int streamIndex, String fileName) throws InsufficientPrivilegeToAccessSessionException, InsufficientPrivilegeToTransferFileOnSessionException, IOException, KavoshServerNotReachableException, KavoshServerNotConfiguredException, GuacamoleException {
      String decodedFileName = URLDecoder.decode(fileName, "UTF-8");
      Capture capture = this.fetchTargetCaptureToTransferFile(sessionId, SessionTransferFileMode.DOWNLOAD, decodedFileName);

      try {
         ManagedSession managedSession = (ManagedSession)SessionManager.getSession(sessionId);
         if (managedSession == null) {
            return outputStream -> outputStream.write(this.objectMapper.writeValueAsString(new SessionNotExistsException(sessionId)).getBytes());
         } else {
            this.checkUserAccessibility(capture);
            if (!managedSession.getAccessRule().getFileTransferMode().equals(FileTransferMode.DOWNLOAD)
               && !managedSession.getAccessRule().getFileTransferMode().equals(FileTransferMode.BOTH)) {
               throw new InsufficientPrivilegeToTransferFileOnSessionException();
            } else {
               StreamInterceptorTunnel tunnel = (StreamInterceptorTunnel)SessionManager.getSession(sessionId).getTunnel();
               boolean scanningEnabled = this.isScanningEnabled(managedSession.getConnection());
               LOGGER.info(
                  Markers.SESSION,
                  "User '{}' requested to download a file named '{}' from connection '{}'{}",
                  this.authorizationService.getCurrentUserInfo().getUsername(),
                  fileName,
                  generateConnectionInfoForLogging(capture),
                  scanningEnabled ? ". File will be sent to Kavosh sever for malware checking before download" : ""
               );
               this.createDirectoriesIfRequired(capture);
               if (scanningEnabled) {
                  SessionScanningTransferredFile sessionScanningTransferredFile = this.sessionScanningTransferredFileService
                     .registerNewFile(capture, decodedFileName);
                  this.asyncTaskExecutor
                     .executeTask(
                        () -> {
                           try {
                              tunnel.interceptStream(
                                 streamIndex,
                                 new BufferedOutputStream(
                                    Files.newOutputStream(this.sessionScanningTransferredFileService.getStoragePath(sessionScanningTransferredFile.getUuid()))
                                 ),
                                 () -> {
                                    try {
                                       this.sessionScanningTransferredFileService.registerFileForScanning(sessionScanningTransferredFile.getUuid());
                                       this.asyncTaskExecutor
                                          .executeTask(
                                             new SessionServiceImpl.DownloadKavoshFileScanningStatusCheckerTask(
                                                sessionScanningTransferredFile,
                                                capture,
                                                SessionTransferFileMode.DOWNLOAD,
                                                this.resolveMaxKavoshResponseWaitTime()
                                             ),
                                             5,
                                             TimeUnit.SECONDS,
                                             true
                                          );
                                    } catch (Exception var5x) {
                                       LOGGER.error(
                                          Markers.SESSION,
                                          "Unexpected error while downloading file '{}' on connection '{}' in remote-session '{}'",
                                          decodedFileName,
                                          generateConnectionInfoForLogging(capture),
                                          capture.getSessionId(),
                                          var5x
                                       );
                                       this.sendUnableToScanFileNotification(sessionScanningTransferredFile.getUuid(), capture.getOwner(), decodedFileName);
                                    }
                                 }
                              );
                           } catch (Exception var7x) {
                              LOGGER.error(
                                 Markers.SESSION,
                                 "Unexpected error while downloading file '{}' on connection '{}' in remote-session '{}'",
                                 decodedFileName,
                                 generateConnectionInfoForLogging(capture),
                                 capture.getSessionId(),
                                 var7x
                              );
                              this.sendUnableToScanFileNotification(sessionScanningTransferredFile.getUuid(), capture.getOwner(), decodedFileName);
                           }
                        }
                     );
                  Response response = Response.information("session.transferring_file.scanning");
                  return outputStream -> outputStream.write(this.objectMapper.writeValueAsString(response).getBytes());
               } else {
                  HttpServletResponse httpServletResponse = (HttpServletResponse) Objects.requireNonNull(
                     ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getResponse()
                  );
                  httpServletResponse.setContentType("application/octet-stream");
                  httpServletResponse.setHeader("Content-Disposition", String.format("attachment; filename=\"%s\"", fileName));
                  return outputStream -> {
                     File file = new File(generateTransferredFilesStoragePath(capture, decodedFileName));

                     try {
                        tunnel.interceptStream(streamIndex, outputStream, new BufferedOutputStream(Files.newOutputStream(file.toPath())), null);
                        this.publishFileTransferringEvent(
                           capture.getSessionId(), decodedFileName, SessionTransferFileMode.DOWNLOAD, SessionTransferredFileStatus.SUCCESSFUL
                        );
                     } catch (Exception var9x) {
                        LOGGER.error(
                           Markers.SESSION,
                           "Unexpected error on downloading file '{}' from connection '{}' in remote-session '{}'",
                           decodedFileName,
                           generateConnectionInfoForLogging(capture),
                           capture.getSessionId()
                        );
                        this.publishFileTransferringEvent(
                           sessionId, decodedFileName, SessionTransferFileMode.DOWNLOAD, SessionTransferredFileStatus.SYSTEM_ERROR
                        );
                        throw new SystemInternalErrorException(var9x);
                     }
                  };
               }
            }
         }
      } catch (InsufficientPrivilegeToTransferFileOnSessionException | InsufficientPrivilegeToAccessSessionException var11) {
         this.publishFileTransferringEvent(sessionId, decodedFileName, SessionTransferFileMode.DOWNLOAD, SessionTransferredFileStatus.ACCESS_DENIED);
         throw var11;
      } catch (Exception var12) {
         LOGGER.error(
            Markers.SESSION,
            "Unexpected error occurred while downloading file '{}' in connection '{}'",
            decodedFileName,
            generateConnectionInfoForLogging(capture),
            var12
         );
         this.publishFileTransferringEvent(sessionId, decodedFileName, SessionTransferFileMode.DOWNLOAD, SessionTransferredFileStatus.SYSTEM_ERROR);
         throw var12;
      }
   }

   @Override
   public void uploadStream(String sessionId, int streamIndex, String fileName) throws InsufficientPrivilegeToAccessSessionException, InsufficientPrivilegeToTransferFileOnSessionException, IOException, KavoshServerNotConfiguredException, KavoshServerNotReachableException, GuacamoleException {
      String decodedFileName = URLDecoder.decode(fileName, "UTF-8");
      Capture capture = this.fetchTargetCaptureToTransferFile(sessionId, SessionTransferFileMode.UPLOAD, decodedFileName);
      HttpServletRequest request = (HttpServletRequest) ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
      HttpServletResponse response = (HttpServletResponse) Objects.requireNonNull(((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getResponse());

      try {
         if (SessionManager.getSession(capture.getSessionId()) == null) {
            response.setHeader("Content-Type", "application/json");
            response.getOutputStream().write(this.objectMapper.writeValueAsString(new SessionNotExistsException(sessionId)).getBytes());
         } else {
            this.checkUserAccessibility(capture);
            ManagedSession managedSession = (ManagedSession)SessionManager.getSession(sessionId);
            if (!managedSession.getAccessRule().getFileTransferMode().equals(FileTransferMode.UPLOAD)
               && !managedSession.getAccessRule().getFileTransferMode().equals(FileTransferMode.BOTH)) {
               throw new InsufficientPrivilegeToTransferFileOnSessionException();
            } else {
               boolean scanningEnabled = this.isScanningEnabled(managedSession.getConnection());
               LOGGER.info(
                  Markers.SESSION,
                  "User '{}' requested to upload a file named '{}' to connection '{}'{}",
                  this.authorizationService.getCurrentUserInfo().getUsername(),
                  decodedFileName,
                  generateConnectionInfoForLogging(capture),
                  scanningEnabled ? ". File will be sent to Kavosh server for malware checking before uploading to target connection" : ""
               );
               this.createDirectoriesIfRequired(capture);
               if (scanningEnabled) {
                  SessionScanningTransferredFile sessionScanningTransferredFile = this.sessionScanningTransferredFileService
                     .registerNewFile(capture, decodedFileName);

                  try {
                     FileUtils.writeToFile(
                        request.getInputStream(), this.sessionScanningTransferredFileService.getStoragePath(sessionScanningTransferredFile.getUuid()).toFile()
                     );
                     Response responseBody = Response.information("session.transferring_file.scanning");
                     response.getOutputStream().write(this.objectMapper.writeValueAsString(responseBody).getBytes());
                     response.getOutputStream().flush();
                     this.sessionScanningTransferredFileService.registerFileForScanning(sessionScanningTransferredFile.getUuid());
                     this.asyncTaskExecutor
                        .executeTask(
                           new SessionServiceImpl.UploadKavoshFileScanningStatusCheckerTask(
                              sessionScanningTransferredFile,
                              capture,
                              SessionTransferFileMode.UPLOAD,
                              this.resolveMaxKavoshResponseWaitTime(),
                              streamIndex,
                              managedSession
                           ),
                           5,
                           TimeUnit.SECONDS,
                           true
                        );
                  } catch (Exception var12) {
                     LOGGER.error(
                        Markers.SESSION,
                        "Unexpected error while uploading file '{}' on connection '{}' in remote-session '{}'",
                        decodedFileName,
                        generateConnectionInfoForLogging(capture),
                        capture.getSessionId(),
                        var12
                     );
                     this.sendUnableToScanFileNotification(sessionScanningTransferredFile.getUuid(), capture.getOwner(), decodedFileName);
                  }
               } else {
                  File file = new File(generateTransferredFilesStoragePath(capture, decodedFileName));
                  StreamInterceptorTunnel tunnel = (StreamInterceptorTunnel)SessionManager.getSession(sessionId).getTunnel();
                  tunnel.interceptStream(streamIndex, request.getInputStream(), new BufferedOutputStream(Files.newOutputStream(file.toPath())), null);
                  this.publishFileTransferringEvent(
                     capture.getSessionId(), decodedFileName, SessionTransferFileMode.UPLOAD, SessionTransferredFileStatus.SUCCESSFUL
                  );
               }
            }
         }
      } catch (InsufficientPrivilegeToTransferFileOnSessionException | InsufficientPrivilegeToAccessSessionException var13) {
         this.publishFileTransferringEvent(sessionId, decodedFileName, SessionTransferFileMode.UPLOAD, SessionTransferredFileStatus.ACCESS_DENIED);
         throw var13;
      } catch (Exception var14) {
         LOGGER.error(
            Markers.SESSION,
            "Unexpected error occurred while uploading file '{}' in connection '{}'",
            decodedFileName,
            generateConnectionInfoForLogging(capture),
            var14
         );
         this.publishFileTransferringEvent(sessionId, decodedFileName, SessionTransferFileMode.UPLOAD, SessionTransferredFileStatus.SYSTEM_ERROR);
         throw var14;
      }
   }

   @Transactional
   @Override
   public void closeTransparentSession(String sessionId) {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      capture.setStatus(CaptureStatus.CLOSED);
      capture.setEndTime(Instant.now().getEpochSecond());
      this.captureRepository.save(capture);
   }

   @Override
   public StreamingResponseBody downloadRequestedFile(String sessionId, String fileUuid) throws FileNotFoundException, InsufficientPrivilegeToAccessSessionException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture);
      File file = this.sessionScanningTransferredFileService.getStoragePath(fileUuid).toFile();

      SessionScanningTransferredFile sessionScanningTransferredFile;
      try {
         sessionScanningTransferredFile = this.sessionScanningTransferredFileService.getByUuid(fileUuid);
      } catch (ResourceNotFoundException var9) {
         sessionScanningTransferredFile = null;
      }

      if (sessionScanningTransferredFile != null && file.exists()) {
         HttpServletResponse httpServletResponse = (HttpServletResponse) Objects.requireNonNull(((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getResponse());

         try {
            return WebUtils.streamFile(httpServletResponse, file, sessionScanningTransferredFile.getFileName(), HttpMimeType.BINARY.getValue());
         } catch (java.io.FileNotFoundException var8) {
            throw new FileNotFoundException();
         }
      } else {
         throw new FileNotFoundException();
      }
   }

   private void checkUserAccessibilityToTerminateSession(Capture capture) throws NoCaptureRuleIsFoundForConnectionException, InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException {
      String connectionName = capture.getConnectionName();
      List<FilterChain> connectionNameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("name", connectionName);
      JpaQuery fetchCaptureRulesOfConnectionQuery = new JpaQueryBuilder()
         .select("cr.id")
         .from(CaptureRule.class, "cr")
         .distinct()
         .join("connections", "c")
         .on(connectionNameFilter)
         .build();
      List<Long> captureRulesOverConnection = this.jpaQueryBasedReadRepository
         .findAll(fetchCaptureRulesOfConnectionQuery, tuple -> Long.parseLong(tuple.get(0).toString()));
      fetchCaptureRulesOfConnectionQuery = new JpaQueryBuilder()
         .select("cr.id")
         .from(CaptureRule.class, "cr")
         .distinct()
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .on(connectionNameFilter)
         .build();
      captureRulesOverConnection.addAll(
         this.jpaQueryBasedReadRepository.findAll(fetchCaptureRulesOfConnectionQuery, tuple -> Long.parseLong(tuple.get(0).toString()))
      );
      if (captureRulesOverConnection.isEmpty()) {
         throw new NoCaptureRuleIsFoundForConnectionException();
      } else {
         List<FilterChain> captureRuleIdsFilter = new FilterChainBuilder()
            .filter(new FilterBuilder().list("id").in(captureRulesOverConnection).buildSingle())
            .build();
         List<FilterChain> userIdFilter = QueryAndFilterUtils.idFilter(this.authorizationService.getCurrentUserInfo().getId());
         JpaQuery searchUserInCaptureRulesQuery = new JpaQueryBuilder()
            .select("cr.id", "cr.disabled", "cr.expirationTime")
            .from(CaptureRule.class, "cr")
            .distinct()
            .join("users", "u")
            .on(userIdFilter)
            .where(captureRuleIdsFilter)
            .build();
         List<Tuple> captureRule = this.jpaQueryBasedReadRepository.findAll(searchUserInCaptureRulesQuery, tuple -> tuple);
         if (captureRule.isEmpty()) {
            searchUserInCaptureRulesQuery = new JpaQueryBuilder()
               .select("cr.id", "cr.disabled", "cr.expirationTime")
               .from(CaptureRule.class, "cr")
               .distinct()
               .join("userGroups", "ug")
               .join("users", "u")
               .on(userIdFilter)
               .where(captureRuleIdsFilter)
               .build();
            captureRule = this.jpaQueryBasedReadRepository.findAll(searchUserInCaptureRulesQuery, tuple -> tuple);
            if (captureRule.isEmpty()) {
               throw new InsufficientPrivilegeToAccessCaptureException();
            }
         }

         if (Boolean.parseBoolean(captureRule.get(0).get(1).toString())) {
            throw new CaptureRuleDisabledException();
         } else {
            int expirationTime = Integer.valueOf(captureRule.get(0).get(2).toString());
            if (expirationTime != 0 && (long)expirationTime <= Instant.now().getEpochSecond()) {
               throw new CaptureRuleExpiredException();
            }
         }
      }
   }

   private void checkUserAccessibility(Capture capture) throws InsufficientPrivilegeToAccessSessionException {
      List<FilterChain> accessRuleUuidFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("uuid", capture.getAccessRuleUuid());
      List<FilterChain> usernameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter(
         "username", this.authorizationService.getCurrentUserInfo().getUsername()
      );
      NativeQuery userExistenceCheckQuery = new NativeQueryBuilder()
         .checkExistence()
         .from(User.class, "u")
         .joinM2M("tb_access_rule_user", "aru", AccessRule.class, "ar")
         .leftOn("id", "user_id")
         .rightOn("access_rule_id", "id")
         .joinWhere(accessRuleUuidFilter)
         .where(usernameFilter)
         .build();
      if (!this.nativeQueryBasedReadRepository.exists(userExistenceCheckQuery)) {
         userExistenceCheckQuery = new NativeQueryBuilder()
            .checkExistence()
            .from(User.class, "u")
            .joinM2M("tb_user_user_group", "uug", UserGroup.class, "ug")
            .leftOn("id", "user_id")
            .rightOn("user_group_id", "id")
            .joinM2M("tb_access_rule_user_group", "arug", AccessRule.class, "ar")
            .leftOn("id", "user_group_id")
            .rightOn("access_rule_id", "id")
            .joinWhere(accessRuleUuidFilter)
            .where(usernameFilter)
            .build();
         if (!this.nativeQueryBasedReadRepository.exists(userExistenceCheckQuery)) {
            throw new InsufficientPrivilegeToAccessSessionException();
         }
      }
   }

   private Capture fetchTargetCaptureToTransferFile(String sessionId, SessionTransferFileMode transferFileMode, String fileName) {
      try {
         return Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      } catch (ResourceNotFoundException var5) {
         this.publishFileTransferringEvent(sessionId, fileName, transferFileMode, SessionTransferredFileStatus.SESSION_NOT_FOUND);
         throw var5;
      }
   }

   private int resolveMaxKavoshResponseWaitTime() {
      return this.maxKavoshResponseWaitTime == 0 ? Integer.MAX_VALUE : this.maxKavoshResponseWaitTime * 60 / 5;
   }

   private void publishFileTransferringEvent(String sessionId, String fileName, SessionTransferFileMode mode, SessionTransferredFileStatus status) {
      this.applicationEventPublisher.publishEvent(new SessionFileTransferringEvent(this, sessionId, fileName, mode, status));
   }

   private void createDirectoriesIfRequired(Capture capture) {
      File file = new File(getSessionFileStoragePath(capture));
      if (!file.exists()) {
         file.mkdirs();
      }
   }

   private boolean isScanningEnabled(Connection connection) {
      if (!connection.getType().equals(ConnectionType.SSH) && !connection.getType().equals(ConnectionType.RDP)) {
         return false;
      } else {
         NativeQuery checkScanningFlagQuery = new NativeQueryBuilder()
            .checkExistence()
            .from(connection.getType().equals(ConnectionType.SSH) ? SshConnection.class : RdpConnection.class)
            .where(
               new FilterChainBuilder()
                  .filter(new FilterBuilder().number("id").eq(connection.getId()).and().bool("malware_scanning_enabled").eq(Boolean.TRUE).build())
                  .build()
            )
            .build();
         return this.nativeQueryBasedReadRepository.exists(checkScanningFlagQuery);
      }
   }

   public static String generateTransferredFilesStoragePath(Capture capture, String fileName) {
      return String.format("%s/%s", getSessionFileStoragePath(capture), fileName);
   }

   public static String getSessionFileStoragePath(Capture capture) {
      return String.format("%s/%s/%s", "/captures/transferred-files", capture.getAccessRuleUuid(), capture.getSessionId());
   }

   private void sendUnableToScanFileNotification(String uuid, String username, String fileName) {
      try {
         SessionScanningTransferredFile sessionScanningTransferredFile = this.sessionScanningTransferredFileService.delete(uuid);
         fileName = sessionScanningTransferredFile.getFileName();
      } catch (ResourceNotFoundException var6) {
      }

      try {
         this.notificationService
            .broadCastMessage(
               new ServerEvent(
                  ServerEventType.MESSAGE,
                  this.messageResolver.getMessage("session.transferred_files.unable_to_scan_file", fileName),
                  SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()
               ),
               Stream.of(username).collect(Collectors.toSet()),
               false
            );
      } catch (SseConnectionBrokenException var5) {
      }
   }

   public static String generateConnectionInfoForLogging(Capture capture) {
      return String.format("%s:%s:%d", capture.getConnectionName(), capture.getConnectionIpAddress(), capture.getConnectionPort());
   }

   private class DownloadKavoshFileScanningStatusCheckerTask extends SessionServiceImpl.KavoshScanningFileStatusCheckerTask {
      private DownloadKavoshFileScanningStatusCheckerTask(
         SessionScanningTransferredFile sessionScanningTransferredFile, Capture capture, SessionTransferFileMode sessionTransferFileMode, int maxIntervals
      ) {
         super(sessionScanningTransferredFile, capture, sessionTransferFileMode, maxIntervals);
      }

      @Override
      protected void onCleanFile() {
         Map<String, String> contentMap = new HashMap<>();
         contentMap.put("url", this.getDownloadUrl(this.capture.getSessionId(), this.sessionScanningTransferredFile.getUuid()));
         contentMap.put("filename", super.sessionScanningTransferredFile.getFileName());
         contentMap.put(
            "size",
            String.valueOf(
               SessionServiceImpl.this.sessionScanningTransferredFileService.getStoragePath(super.sessionScanningTransferredFile.getUuid()).toFile().length()
            )
         );

         try {
            String content = SessionServiceImpl.this.objectMapper.writeValueAsString(contentMap);
            SessionServiceImpl.this.notificationService
               .broadCastMessage(
                  new ServerEvent(ServerEventType.DOWNLOAD, content, SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()),
                  Collections.singleton(super.capture.getOwner())
               );
            SessionServiceImpl.this.asyncTaskExecutor
               .executeTask(
                  () -> SessionServiceImpl.this.sessionScanningTransferredFileService.delete(super.sessionScanningTransferredFile.getUuid()), 6, TimeUnit.HOURS
               );
         } catch (Exception var3) {
            SessionServiceImpl.LOGGER
               .warn(Markers.SESSION, "Could not send session download link to user for file '{}'", super.sessionScanningTransferredFile.getFileName(), var3);
            SessionServiceImpl.this.sessionScanningTransferredFileService.delete(super.sessionScanningTransferredFile.getUuid());
         }
      }

      @Override
      protected void onInfectedFile() {
      }

      private String getDownloadUrl(String sessionId, String uuid) {
         return String.format("/api/sessions/%s/requested-files/%s", sessionId, uuid);
      }
   }

   private abstract class KavoshScanningFileStatusCheckerTask implements Runnable {
      private static final String MALWARE_NOTIFICATION_CODE = "session.transferred_files.infected";
      protected final SessionScanningTransferredFile sessionScanningTransferredFile;
      protected final Capture capture;
      protected final SessionTransferFileMode sessionTransferFileMode;
      protected final int maxIntervals;
      private int counter = 0;

      private KavoshScanningFileStatusCheckerTask(
         SessionScanningTransferredFile sessionScanningTransferredFile, Capture capture, SessionTransferFileMode sessionTransferFileMode, int maxIntervals
      ) {
         this.sessionScanningTransferredFile = sessionScanningTransferredFile;
         this.capture = capture;
         this.sessionTransferFileMode = sessionTransferFileMode;
         this.maxIntervals = maxIntervals;
      }

      protected abstract void onCleanFile();

      protected abstract void onInfectedFile();

      @Override
      public void run() {
         this.counter++;
         if (this.counter > this.maxIntervals) {
            this.sendUnableToScanNotification();
         }

         KavoshIntegrationService.FileStatus status = null;
         Exception exception = null;

         try {
            status = SessionServiceImpl.this.sessionScanningTransferredFileService.checkStatus(this.sessionScanningTransferredFile.getUuid());
         } catch (Exception var6) {
            exception = var6;
         }

         if (exception != null) {
            SessionServiceImpl.LOGGER
               .error(
                  Markers.SESSION,
                  "Could not check Kavosh scanning status for file '{}' over connection '{}'",
                  this.sessionScanningTransferredFile.getFileName(),
                  SessionServiceImpl.generateConnectionInfoForLogging(this.capture),
                  exception
               );
            this.sendUnableToScanNotification();
         } else {
            if (status.equals(KavoshIntegrationService.FileStatus.SCANNING)) {
               SessionServiceImpl.this.asyncTaskExecutor.executeTask(this, 5, TimeUnit.SECONDS, true);
            } else {
               try {
                  if (status.equals(KavoshIntegrationService.FileStatus.CLEAN)) {
                     SessionServiceImpl.LOGGER
                        .debug(
                           Markers.SESSION,
                           "Kavosh has marked file '{}' on connection '{}' as 'clean'. About to complete file transfer",
                           this.sessionScanningTransferredFile.getFileName(),
                           SessionServiceImpl.generateConnectionInfoForLogging(this.sessionScanningTransferredFile.getCapture())
                        );
                     this.finalizeSuccessfulFileTransfer();
                     this.onCleanFile();
                  } else {
                     SessionServiceImpl.LOGGER
                        .debug(
                           Markers.SESSION,
                           "Kavosh has marked file '{}' on connection '{}' as 'malware'. About to complete file transfer",
                           this.sessionScanningTransferredFile.getFileName(),
                           SessionServiceImpl.generateConnectionInfoForLogging(this.sessionScanningTransferredFile.getCapture())
                        );
                     this.onInfectedFile();
                     SessionServiceImpl.this.publishFileTransferringEvent(
                        this.capture.getSessionId(),
                        this.sessionScanningTransferredFile.getFileName(),
                        this.sessionTransferFileMode,
                        SessionTransferredFileStatus.MALWARE
                     );
                     SessionServiceImpl.LOGGER
                        .info(
                           Markers.SESSION,
                           "Server prevented transferring file '{}' over connection '{}' cause Kavosh detected it as malware",
                           this.sessionScanningTransferredFile.getFileName(),
                           SessionServiceImpl.generateConnectionInfoForLogging(this.capture)
                        );
                     SessionServiceImpl.this.notificationService
                        .broadCastMessage(
                           new ServerEvent(
                              ServerEventType.MESSAGE,
                              SessionServiceImpl.this.messageResolver
                                 .getMessage("session.transferred_files.infected", this.sessionScanningTransferredFile.getFileName()),
                              SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()
                           ),
                           Stream.of(this.capture.getOwner()).collect(Collectors.toSet()),
                           false
                        );
                     SessionServiceImpl.this.sessionScanningTransferredFileService.delete(this.sessionScanningTransferredFile.getUuid());
                  }
               } catch (SseConnectionBrokenException var4) {
               } catch (Exception var5) {
                  SessionServiceImpl.LOGGER
                     .error(
                        Markers.SESSION,
                        "Unexpected error occurred on processing Kavosh scanning result for file '{}' over connection '{}'",
                        this.sessionScanningTransferredFile.getFileName(),
                        SessionServiceImpl.generateConnectionInfoForLogging(this.capture)
                     );
                  this.sendUnableToScanNotification();
                  SessionServiceImpl.this.sessionScanningTransferredFileService.delete(this.sessionScanningTransferredFile.getUuid());
               }
            }
         }
      }

      private void finalizeSuccessfulFileTransfer() throws IOException {
         Path source = SessionServiceImpl.this.sessionScanningTransferredFileService.getStoragePath(this.sessionScanningTransferredFile.getUuid());
         Path target = Paths.get(SessionServiceImpl.generateTransferredFilesStoragePath(this.capture, this.sessionScanningTransferredFile.getFileName()));
         Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
         SessionServiceImpl.this.publishFileTransferringEvent(
            this.capture.getSessionId(),
            this.sessionScanningTransferredFile.getFileName(),
            this.sessionTransferFileMode,
            SessionTransferredFileStatus.SUCCESSFUL
         );
      }

      private void sendUnableToScanNotification() {
         SessionServiceImpl.this.sendUnableToScanFileNotification(
            this.sessionScanningTransferredFile.getUuid(), this.capture.getOwner(), this.sessionScanningTransferredFile.getFileName()
         );
      }
   }

   private class UploadKavoshFileScanningStatusCheckerTask extends SessionServiceImpl.KavoshScanningFileStatusCheckerTask {
      private final int streamIndex;
      private final Session session;

      private UploadKavoshFileScanningStatusCheckerTask(
         SessionScanningTransferredFile sessionScanningTransferredFile,
         Capture capture,
         SessionTransferFileMode sessionTransferFileMode,
         int maxIntervals,
         int streamIndex,
         ManagedSession session
      ) {
         super(sessionScanningTransferredFile, capture, sessionTransferFileMode, maxIntervals);
         this.streamIndex = streamIndex;
         this.session = session;
      }

      @Override
      protected void onCleanFile() {
         try {
            ((StreamInterceptorTunnel)this.session.getTunnel())
               .interceptStream(
                  this.streamIndex,
                  new BufferedInputStream(
                     new FileInputStream(
                        SessionServiceImpl.this.sessionScanningTransferredFileService.getStoragePath(super.sessionScanningTransferredFile.getUuid()).toFile()
                     )
                  ),
                  new BufferedOutputStream(
                     new FileOutputStream(
                        SessionServiceImpl.generateTransferredFilesStoragePath(super.capture, super.sessionScanningTransferredFile.getFileName())
                     )
                  ),
                  null
               );
         } catch (Exception var2) {
            SessionServiceImpl.LOGGER
               .error(
                  Markers.SESSION,
                  "Unexpected error on uploading scanned file '{}' to target server '{}'",
                  super.sessionScanningTransferredFile.getFileName(),
                  SessionServiceImpl.generateConnectionInfoForLogging(super.capture),
                  var2
               );
            SessionServiceImpl.this.sessionScanningTransferredFileService.delete(super.sessionScanningTransferredFile.getUuid());
         }
      }

      @Override
      protected void onInfectedFile() {
         try {
            ((StreamInterceptorTunnel)this.session.getTunnel()).interceptStream(this.streamIndex, new ByteArrayInputStream(new byte[0]), null, null);
         } catch (GuacamoleException var2) {
            var2.printStackTrace();
         }
      }
   }
}
