package ir.fidar.pam.session.websocket;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.domain.dto.management.notification.ServerEvent;
import ir.fidar.core.domain.dto.management.notification.ServerEventType;
import ir.fidar.core.exception.SseConnectionBrokenException;
import ir.fidar.core.exception.management.setting.email.EmailSenderConfigurationNotRegisteredException;
import ir.fidar.core.exception.management.setting.sms.SmsSenderConfigurationNotRegisteredException;
import ir.fidar.core.management.SystemConstantsAndDefaults;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.security.service.AuthorizationService;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.da.repository.SessionCapturedImageRepository;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.SessionTimeoutSetting;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.service.SessionTimeoutSettingService;
import ir.fidar.pam.session.BridgeSessionConfigurationParameterResolver;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.SessionManager;
import ir.fidar.pam.session.exception.SessionInputValidationException;
import ir.fidar.pam.session.filters.CachedBufferSessionInputSessionInputValidator;
import ir.fidar.pam.session.filters.ClipboardInstructionFilter;
import ir.fidar.pam.session.filters.DisconnectInstructionFilter;
import ir.fidar.pam.session.filters.KeyPressedSessionFilter;
import ir.fidar.pam.session.filters.KeyReleasedSessionFilter;
import ir.fidar.pam.session.filters.MouseClickedFilter;
import ir.fidar.pam.session.filters.MouseRightClickedFilter;
import ir.fidar.pam.session.filters.SessionInputValidator;
import ir.fidar.pam.session.filters.SyncInstructionFilter;
import ir.fidar.pam.session.filters.TabKeyFilter;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionExtractionTaskRegistry;
import ir.fidar.pam.session.inputextraction.service.RemoteSessionInputExtractionService;
import ir.fidar.pam.session.ocr.OcrHostProperties;
import ir.fidar.pam.session.ocr.OcrRequest;
import ir.fidar.pam.session.ocr.OcrRequestExecutor;
import ir.fidar.pam.session.ocr.OcrRequestType;
import ir.fidar.pam.session.ocr.OcrStorageFolderWatcher;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import jakarta.persistence.EntityManagerFactory;
import org.apache.guacamole.GuacamoleConnectionClosedException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.io.GuacamoleWriter;
import org.apache.guacamole.io.ReaderGuacamoleReader;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;

@Component
public class BridgeWebsocketSessionHandler extends BridgeWebsocketHandler implements DisposableBean {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String COMMON_LOG_MESSAGE_FORMAT = "%s session '{}' to connection '{}' through access-rule '{}'";
   private static final String COMMAND_EXECUTION_PREVENTION_INSTRUCTION = "3.key,5.65507,1.1;3.key,2.99,1.1;3.key,5.65507,1.0;3.key,2.99,1.0;";
   private static final String DISCONNECT_INSTRUCTION = "10.disconnect;";
   private final BridgeSessionConfigurationParameterResolver sessionConfigurationParameterSetter;
   private final AuthorizationService authorizationService;
   private final EntityManagerFactory entityManagerFactory;
   private final SessionTimeoutSettingService sessionTimeoutSettingService;
   private final NotificationService notificationService;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private final CaptureService captureService;
   private final RemoteSessionInputExtractionService inputExtractionManager;
   private final OcrHostProperties ocrHostProperties;
   private final SessionCapturedImageRepository sessionCapturedImageRepository;
   private SessionInputValidator sessionInputValidator;
   private final EmailSender emailSender;
   private final SmsSender smsSender;
   private final MouseClickedFilter mouseClickedFilter;
   private final MouseRightClickedFilter mouseRightClickedFilter;
   private final KeyPressedSessionFilter keyPressedSessionFilter;
   private final KeyReleasedSessionFilter keyReleasedSessionFilter;
   private final ClipboardInstructionFilter clipboardInstructionFilter;
   private final SyncInstructionFilter syncInstructionFilter;
   private final DisconnectInstructionFilter disconnectInstructionFilter;
   private final TabKeyFilter tabKeyFilter;
   private int sessionTimeoutThreshold;
   private boolean reactiveByMouseMovement;
   private long sessionLastActivityTime;
   private GuacamoleInstruction lastPressedKey = null;
   private ManagedSession managedSession;
   private volatile boolean bridgeDisconnectReceived = false;
   private volatile boolean bridgeConnectionClosed = false;
   private volatile boolean clientDisconnectReceived = false;
   private volatile WebsocketSessionCloseStatus closeStatus = null;
   private final Lock CLOSE_LOCK = new ReentrantLock();
   private OcrRequestExecutor ocrRequestExecutor;
   private OcrStorageFolderWatcher ocrStorageFolderWatcher;

   public BridgeWebsocketSessionHandler(
      BridgeSessionConfigurationParameterResolver sessionConfigurationParameterSetter,
      AuthorizationService authorizationService,
      EntityManagerFactory entityManagerFactory,
      SessionTimeoutSettingService sessionTimeoutSettingService,
      NotificationService notificationService,
      AsyncTaskExecutor asyncTaskExecutor,
      CaptureService captureService,
      RemoteSessionInputExtractionService inputExtractionManager,
      OcrHostProperties ocrHostProperties,
      SessionCapturedImageRepository sessionCapturedImageRepository,
      EmailSender emailSender,
      SmsSender smsSender,
      MouseClickedFilter mouseClickedFilter,
      MouseRightClickedFilter mouseRightClickedFilter,
      KeyPressedSessionFilter keyPressedSessionFilter,
      KeyReleasedSessionFilter keyReleasedSessionFilter,
      ClipboardInstructionFilter clipboardInstructionFilter,
      SyncInstructionFilter syncInstructionFilter,
      DisconnectInstructionFilter disconnectInstructionFilter,
      TabKeyFilter tabKeyFilter
   ) {
      this.sessionConfigurationParameterSetter = sessionConfigurationParameterSetter;
      this.authorizationService = authorizationService;
      this.entityManagerFactory = entityManagerFactory;
      this.sessionTimeoutSettingService = sessionTimeoutSettingService;
      this.notificationService = notificationService;
      this.asyncTaskExecutor = asyncTaskExecutor;
      this.captureService = captureService;
      this.inputExtractionManager = inputExtractionManager;
      this.ocrHostProperties = ocrHostProperties;
      this.sessionCapturedImageRepository = sessionCapturedImageRepository;
      this.emailSender = emailSender;
      this.smsSender = smsSender;
      this.mouseClickedFilter = mouseClickedFilter;
      this.mouseRightClickedFilter = mouseRightClickedFilter;
      this.keyPressedSessionFilter = keyPressedSessionFilter;
      this.keyReleasedSessionFilter = keyReleasedSessionFilter;
      this.clipboardInstructionFilter = clipboardInstructionFilter;
      this.syncInstructionFilter = syncInstructionFilter;
      this.disconnectInstructionFilter = disconnectInstructionFilter;
      this.tabKeyFilter = tabKeyFilter;
   }

   public boolean isAlive() {
      return !this.bridgeConnectionClosed && !this.clientDisconnectReceived;
   }

   @Override
   public synchronized void setCloseStatus(WebsocketSessionCloseStatus closeStatus) {
      if (this.closeStatus == null) {
         this.closeStatus = closeStatus;
      }
   }

   public void afterConnectionEstablished(WebSocketSession webSocketSession) throws Exception {
      this.initializeContexts(webSocketSession);
      Map<String, Object> attributes = webSocketSession.getAttributes();
      AccessRuleConnection accessRuleConnection = (AccessRuleConnection)attributes.get(WebsocketSessionAttributeKey.UNDERLYING_ACCESS_RULE.toString());
      AccessRule accessRule = accessRuleConnection.getAccessRule();
      Connection connection = accessRuleConnection.getConnection();
      Exception exception = null;
      LOGGER.debug(
         Markers.SESSION,
         "About to establish '{}' session to connection '{}' through access-rule '{}' [uuid = {}]",
         connection.getType().toString(),
         connection.getName(),
         accessRule.getName(),
         accessRule.getUuid()
      );

      try {
         WebsocketSessionCloseStatus closeStatus = (WebsocketSessionCloseStatus)attributes.get(WebsocketSessionAttributeKey.CLOSE_STATUS.toString());
         if (closeStatus != null) {
            this.setCloseStatus(closeStatus);
         } else if (!this.checkForAccessibilityTimeConstraint(
            (List<AccessibilityTimePeriodConstraint>)attributes.get(WebsocketSessionAttributeKey.ACCESSIBILITY_TIME_CONSTRAINT.toString())
         )) {
            this.setCloseStatus(WebsocketSessionCloseStatus.TERMINATED_BY_ACCESSIBILITY_TIME_CONSTRAINT);
         }

         GuacamoleClientInformation clientInformation = (GuacamoleClientInformation)attributes.get(WebsocketSessionAttributeKey.CLIENT_INFORMATION.toString());
         String sessionUuid = UUID.randomUUID().toString();

         while (this.captureService.isSessionIdAlreadyRegistered(sessionUuid)) {
            sessionUuid = UUID.randomUUID().toString();
         }

         GuacamoleConfiguration guacamoleConfiguration = new GuacamoleConfiguration();
         guacamoleConfiguration.setParameters(this.sessionConfigurationParameterSetter.resolve(accessRule, accessRuleConnection, sessionUuid));
         guacamoleConfiguration.setProtocol(connection.getType().toString().toLowerCase());
         String ipAddress = accessRule.getBridge().getIpAddress();
         int port = accessRule.getBridge().getPort();
         ConfiguredGuacamoleSocket socket = new ConfiguredGuacamoleSocket(new InetGuacamoleSocket(ipAddress, port), guacamoleConfiguration, clientInformation);
         this.managedSession = new ManagedSession(
            sessionUuid, accessRule, accessRuleConnection, this.authorizationService.getCurrentUserInfo().getUsername(), socket, clientInformation, this
         );
         LOGGER.debug(
            Markers.SESSION,
            String.format("%s session '{}' to connection '{}' through access-rule '{}'", "Parameters are set and ManagedSession instance is created for"),
            sessionUuid,
            connection.getName(),
            accessRule.getName()
         );
         this.captureService.create(this.managedSession);
         if (this.closeStatus != null) {
            this.clientDisconnectReceived = true;
            this.bridgeConnectionClosed = true;
            this.close(webSocketSession);
            return;
         }

         if (accessRule.getExpirationTime() != 0L) {
            this.asyncTaskExecutor.executeTask(() -> {
               if (this.isAlive()) {
                  this.setCloseStatus(WebsocketSessionCloseStatus.EXPIRED_ACCESS_RULE);
               }
            }, 0, Integer.parseInt(String.valueOf(accessRule.getExpirationTime() - Instant.now().getEpochSecond())) + 3, TimeUnit.SECONDS);
         }

         if (accessRule.isOcrEnabled()) {
            this.ocrRequestExecutor = new OcrRequestExecutor(this.ocrHostProperties);
            new File(String.format("%s/%s", this.ocrHostProperties.getStoragePath(), sessionUuid)).mkdir();
            this.ocrRequestExecutor.startListening();
            Map<String, String> query = new HashMap<>();
            query.put("width", String.valueOf(clientInformation.getOptimalScreenWidth()));
            query.put("height", String.valueOf(clientInformation.getOptimalScreenHeight()));
            query.put("type", "fake-session");
            this.ocrRequestExecutor.registerRequest(new OcrRequest(sessionUuid, OcrRequestType.INIT, query));
            this.ocrStorageFolderWatcher = new OcrStorageFolderWatcher(sessionUuid, this.sessionCapturedImageRepository, this.ocrHostProperties);
            new Thread(this.ocrStorageFolderWatcher).start();
            LOGGER.debug(
               Markers.SESSION,
               String.format("%s session '{}' to connection '{}' through access-rule '{}'", "OCR services are initialized and started for"),
               sessionUuid,
               connection.getName(),
               accessRule.getName()
            );
         }

         SessionManager.registerSession(this.managedSession);
         if (!accessRule.isBastion()) {
            accessRule.getSessionInputConstraints().add(this.generateBastionSessionInputConstraintHandler());
         }

         if (!accessRule.getSessionInputConstraints().isEmpty()) {
            this.sessionInputValidator = new CachedBufferSessionInputSessionInputValidator(accessRule.getSessionInputConstraints());
            LOGGER.debug(
               Markers.SESSION,
               String.format("%s session '{}' to connection '{}' through access-rule '{}'", "Session input constraint list {} is set on"),
               accessRule.getSessionInputConstraints()
                  .stream()
                  .map(sessionInputConstraintViolationHandler -> sessionInputConstraintViolationHandler.getInputConstraint().getRegex())
                  .collect(Collectors.toSet())
                  .toString(),
               sessionUuid,
               connection.getName(),
               accessRule.getName()
            );
         }

         this.initializeSessionTimeout(connection);
         LOGGER.debug(
            Markers.SESSION,
            String.format("%s session '{}' to connection '{}' through access-rule '{}'", "Session timeout checker is initialized and started for"),
            sessionUuid,
            connection.getName(),
            accessRule.getName()
         );

         try {
            this.inputExtractionManager.registerNewSession(this.managedSession);
         } catch (Exception var20) {
            LOGGER.error(
               Markers.SESSION,
               "Unexpected error occurred on registering new session for input extraction processing. Session-ID: {}. Closing session",
               this.managedSession.getId(),
               var20
            );
            this.managedSession.getWebsocketHandler().setCloseStatus(WebsocketSessionCloseStatus.INTERNAL_ERROR);
            this.managedSession.close();
            return;
         }

         this.managedSession.open();
         Thread thread = new BridgeWebsocketSessionHandler.BridgeReader(webSocketSession, sessionUuid);
         thread.start();
         LOGGER.debug(
            Markers.SESSION,
            String.format("%s session '{}' to connection '{}' through access-rule '{}'", "Bridge reader thread [{}] is started for"),
            thread.getName(),
            sessionUuid,
            connection.getName(),
            accessRule.getName()
         );
         LOGGER.info(
            Markers.SESSION,
            "'{}' session is successfully established to connection '{}' through access-rule '{}'. session id: {}",
            connection.getType().toString(),
            connection.getName(),
            accessRule.getName(),
            sessionUuid
         );
      } catch (GuacamoleException var21) {
         LOGGER.error(
            Markers.SESSION,
            "An unexpected error is occurred on establishing connection to bridge for connection '{}' through access-rule '{}' when trying to initialize bridge",
            connection.getName(),
            accessRule.getName(),
            var21
         );
         this.setCloseStatus(WebsocketSessionCloseStatus.BRIDGE_CONNECTION_ERROR);
         exception = var21;
      } catch (Exception var22) {
         LOGGER.error(
            Markers.SESSION,
            "An unexpected error is occurred on establishing session to connection '{}' through access-rule '{}'",
            connection.getName(),
            accessRule.getName(),
            var22
         );
         this.setCloseStatus(WebsocketSessionCloseStatus.INTERNAL_ERROR);
         exception = var22;
      } finally {
         if (exception != null) {
            this.close(webSocketSession);
         }
      }

      this.clearContexts();
   }

   protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
      String content = (String)message.getPayload();
      GuacamoleInstruction instruction = this.readInstruction(content);
      this.submitExtractionTask(content, InputSource.CLIENT);
      if (this.disconnectInstructionFilter.filter(instruction) != null) {
         this.clientDisconnectReceived = true;
         if (this.bridgeConnectionClosed) {
            this.close(session);
         } else {
            try {
               this.sendDisconnectInstructionToBridge();
            } catch (GuacamoleException var9) {
               this.bridgeConnectionClosed = true;
               this.close(session);
            }
         }
      } else if (this.closeStatus != null) {
         if (this.bridgeConnectionClosed) {
            session.sendMessage(new TextMessage("10.disconnect;"));
         } else {
            if (this.lastPressedKey != null) {
               GuacamoleWriter writer = this.managedSession.getTunnel().acquireWriter();
               List<String> args = new ArrayList<>(this.lastPressedKey.getArgs());
               args.set(1, "0");
               GuacamoleInstruction keyReleaseInstruction = new GuacamoleInstruction(this.lastPressedKey.getOpcode(), args);
               writer.write(keyReleaseInstruction.toString().toCharArray());
               this.managedSession.getTunnel().releaseWriter();
               this.lastPressedKey = null;
            }

            try {
               this.sendDisconnectInstructionToBridge();
            } catch (GuacamoleException var10) {
               this.close(session);
            }
         }
      } else {
         boolean resetLastActivityTime = false;
         boolean isKeyPressed = this.keyPressedSessionFilter.filter(instruction) != null;
         if (isKeyPressed) {
            this.lastPressedKey = instruction;
            resetLastActivityTime = true;
            if (this.sessionInputValidator != null) {
               try {
                  this.sessionInputValidator.validate(instruction);
               } catch (SessionInputValidationException var11) {
                  LOGGER.info(
                     Markers.SESSION, "Input Constraint violated. regex: {}, input: {}", var11.getHandler().getInputConstraint().getRegex(), var11.getInput()
                  );
                  this.asyncTaskExecutor
                     .executeTask(
                        () -> this.registerSessionInputConstraintIncident(
                              this.managedSession, var11.getInput(), var11.getHandler().getInputConstraint().getRegex()
                           )
                     );
                  SessionInputConstraintViolationHandler handler = var11.getHandler();
                  if (handler.isSendNotification()) {
                     this.asyncTaskExecutor
                        .executeTask(
                           () -> {
                              try {
                                 ServerEvent serverEvent = new ServerEvent(
                                    ServerEventType.MESSAGE,
                                    String.format("You have violated an input constraint by entering '%s'", var11.getInput()),
                                    SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()
                                 );
                                 this.notificationService.broadCastMessage(serverEvent, Collections.singleton(session.getPrincipal().getName()));
                              } catch (SseConnectionBrokenException var4x) {
                                 LOGGER.error(
                                    Markers.SESSION,
                                    "SSE Connection is broken. Could not sent notification to user '{}' for input constraint violation",
                                    session.getPrincipal().getName()
                                 );
                              }
                           }
                        );
                  }

                  if (handler.isAlertSomeone()) {
                     if (StringUtils.hasContent(handler.getEmail())) {
                        this.asyncTaskExecutor
                           .executeTask(
                              new BridgeWebsocketSessionHandler.SendEmailTask(
                                 session.getPrincipal().getName(), handler.getEmail(), handler.getInputConstraint().getRegex(), var11.getInput()
                              )
                           );
                     }

                     if (StringUtils.hasContent(handler.getPhoneNumber())) {
                        this.asyncTaskExecutor
                           .executeTask(
                              new BridgeWebsocketSessionHandler.SendSmsTask(
                                 session.getPrincipal().getName(), handler.getPhoneNumber(), handler.getInputConstraint().getRegex(), var11.getInput()
                              )
                           );
                     }
                  }

                  if (handler.isTerminateSession()) {
                     content = "3.key,5.65507,1.1;3.key,2.99,1.1;3.key,5.65507,1.0;3.key,2.99,1.0;";
                     this.setCloseStatus(WebsocketSessionCloseStatus.TERMINATED_BY_INPUT_CONSTRAINT);
                  } else if (handler.isPreventExecution()) {
                     content = "3.key,5.65507,1.1;3.key,2.99,1.1;3.key,5.65507,1.0;3.key,2.99,1.0;";
                  }
               }
            }
         } else if (this.keyReleasedSessionFilter.filter(instruction) != null) {
            this.lastPressedKey = null;
         } else if (this.syncInstructionFilter.filter(instruction) == null) {
            resetLastActivityTime = this.reactiveByMouseMovement || this.mouseClickedFilter.filter(instruction) != null;
         }

         if (this.sessionTimeoutThreshold != 0) {
            long now = Instant.now().getEpochSecond();
            if (resetLastActivityTime) {
               this.sessionLastActivityTime = now;
            } else if (now - this.sessionLastActivityTime > (long)this.sessionTimeoutThreshold) {
               this.setCloseStatus(WebsocketSessionCloseStatus.TERMINATED_DUE_TO_INACTIVITY);
            }
         }

         if (this.clipboardInstructionFilter.filter(instruction) == null || this.managedSession.getAccessRule().isClipboard()) {
            GuacamoleWriter writer = this.managedSession.getTunnel().acquireWriter();
            writer.write(content.toCharArray());
            this.managedSession.getTunnel().releaseWriter();
         }
      }
   }

   @Override
   public void close(WebSocketSession session) {
      synchronized (this.CLOSE_LOCK) {
         if (this.closeStatus == null) {
            this.setCloseStatus(WebsocketSessionCloseStatus.NORMAL);
         }

         try {
            if (this.managedSession != null) {
               this.closeBridgeConnectionAndFreeUpResources();
            }

            if (session.isOpen()) {
               session.close(new CloseStatus(this.closeStatus.getCode(), this.closeStatus.getStatus()));
            }
         } catch (Exception var9) {
            LOGGER.error(Markers.SESSION, "An unexpected error occurred when closing web-socket for session '{}'", this.managedSession.getId(), var9);
         } finally {
            this.CLOSE_LOCK.notify();
         }
      }
   }

   public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
      synchronized (this.CLOSE_LOCK) {
         if (!this.clientDisconnectReceived) {
            this.clientDisconnectReceived = true;
            this.sendDisconnectInstructionToBridge();
            this.CLOSE_LOCK.wait();
            LOGGER.info(
               Markers.SESSION,
               "'{}' session '{}' to connection '{}' through access-rule '{}' is closed successfully. reason: {}",
               this.managedSession.getConnection().getType().toString(),
               this.managedSession.getId(),
               this.managedSession.getConnection().getName(),
               this.managedSession.getAccessRule().getName(),
               this.closeStatus.getStatus()
            );
         }

         this.inputExtractionManager.finalizeExtraction(this.managedSession.getId());
      }

      ThreadContext.clearAll();
   }

   public void destroy() throws Exception {
      this.managedSession = null;
      this.clearContexts();
      if (this.ocrRequestExecutor != null) {
         this.ocrRequestExecutor.shutDown();
      }

      if (this.ocrStorageFolderWatcher != null) {
         this.ocrStorageFolderWatcher.close();
      }
   }

   private void closeBridgeConnectionAndFreeUpResources() {
      String sessionId = this.managedSession.getId();
      LOGGER.debug(Markers.SESSION, "About to close session '{}'", sessionId);
      ManagedSession managedSession = (ManagedSession)SessionManager.terminateSession(sessionId);
      if (managedSession != null) {
         LOGGER.debug(Markers.SESSION, "Session '{}' is removed from session manager", sessionId);
         this.captureService.close(managedSession);
         if (this.ocrRequestExecutor != null) {
            this.ocrRequestExecutor.registerRequest(new OcrRequest(managedSession.getId(), OcrRequestType.CLOSE, null));
            this.ocrRequestExecutor.shutDown();
            this.ocrStorageFolderWatcher.close();
            LOGGER.debug(
               Markers.SESSION,
               String.format("%s session '{}' to connection '{}' through access-rule '{}'", "OCR related services/tasks are shutdown for"),
               sessionId,
               managedSession.getConnection().getName(),
               managedSession.getAccessRule().getName()
            );
         }
      } else {
         Capture capture = this.captureService.getBySessionId(sessionId);
         if (capture != null) {
            if (capture.getEndTime() == 0L) {
               capture.setEndTime((long)Long.valueOf(Instant.now().getEpochSecond()).intValue());
            }

            capture.setStatus(CaptureStatus.CLOSED);
            this.captureService.saveCapture(capture);
         }
      }
   }

   private void sendDisconnectInstructionToBridge() throws GuacamoleException {
      GuacamoleWriter writer = this.managedSession.getTunnel().acquireWriter();
      writer.write("10.disconnect;".toCharArray());
      this.managedSession.getTunnel().releaseWriter();
   }

   private GuacamoleInstruction readInstruction(String content) throws GuacamoleException {
      GuacamoleReader reader = new ReaderGuacamoleReader(new StringReader(content));
      return reader.readInstruction();
   }

   private boolean checkForAccessibilityTimeConstraint(List<AccessibilityTimePeriodConstraint> accessibilityTimePeriodConstraints) {
      if (accessibilityTimePeriodConstraints == null) {
         return true;
      } else {
         ZonedDateTime now = Instant.now().atZone(ZoneId.of("Z"));

         for (AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint : accessibilityTimePeriodConstraints) {
            String timezone = accessibilityTimePeriodConstraint.getTimezone();
            switch (accessibilityTimePeriodConstraint.getMode()) {
               case DAILY:
                  DailyAccessibilityTimePeriodConstraint dailyAccessibilityTimePeriodConstraint = accessibilityTimePeriodConstraint.getDailyConstraint();
                  if (!this.validateTimeConstraint(
                     dailyAccessibilityTimePeriodConstraint.getFromHour(),
                     dailyAccessibilityTimePeriodConstraint.getFromMinute(),
                     dailyAccessibilityTimePeriodConstraint.getToHour(),
                     dailyAccessibilityTimePeriodConstraint.getToMinute(),
                     now,
                     timezone
                  )) {
                     return false;
                  }
                  break;
               case WEEKLY:
                  List<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraintList = accessibilityTimePeriodConstraint.getWeeklyConstraints(
                     
                  );
                  List<WeeklyAccessibilityTimePeriodConstraint> filteredWeeklyAccessibilityTimePeriodConstraintList = weeklyAccessibilityTimePeriodConstraintList.stream(
                        
                     )
                     .filter(weeklyAccessibilityTimePeriodConstraint -> {
                        int code = weeklyAccessibilityTimePeriodConstraint.getWeekDay().getCode();
                        code -= 2;
                        if (code <= 0) {
                           code += 7;
                        }
   
                        return code == now.getDayOfWeek().getValue();
                     })
                     .collect(Collectors.toList());
                  if (filteredWeeklyAccessibilityTimePeriodConstraintList.isEmpty()) {
                     return false;
                  }

                  Collections.sort(filteredWeeklyAccessibilityTimePeriodConstraintList, (o1, o2) -> {
                     if (o1.getFromHour() < o2.getFromHour()) {
                        return -1;
                     } else if (o1.getFromHour() > o2.getFromHour()) {
                        return 1;
                     } else if (o1.getFromMinute() < o2.getFromMinute()) {
                        return -1;
                     } else {
                        return o1.getFromMinute() > o2.getFromMinute() ? 1 : 0;
                     }
                  });

                  for (int i = 0; i < filteredWeeklyAccessibilityTimePeriodConstraintList.size(); i++) {
                     WeeklyAccessibilityTimePeriodConstraint weeklyAccessibilityTimePeriodConstraint = filteredWeeklyAccessibilityTimePeriodConstraintList.get(
                        i
                     );
                     if (this.validateTimeConstraint(
                        weeklyAccessibilityTimePeriodConstraint.getFromHour(),
                        weeklyAccessibilityTimePeriodConstraint.getFromMinute(),
                        weeklyAccessibilityTimePeriodConstraint.getToHour(),
                        weeklyAccessibilityTimePeriodConstraint.getToMinute(),
                        now,
                        timezone
                     )) {
                        break;
                     }

                     if (i == filteredWeeklyAccessibilityTimePeriodConstraintList.size() - 1) {
                        return false;
                     }
                  }
                  break;
               case MONTHLY:
                  List<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraints = accessibilityTimePeriodConstraint.getMonthlyConstraints(
                     
                  );
                  List<MonthlyAccessibilityTimePeriodConstraint> filteredMonthlyAccessibilityTimePeriodConstraintList = monthlyAccessibilityTimePeriodConstraints.stream(
                        
                     )
                     .filter(monthlyAccessibilityTimePeriodConstraintx -> monthlyAccessibilityTimePeriodConstraintx.getMonthDay() == now.getDayOfMonth())
                     .collect(Collectors.toList());
                  if (filteredMonthlyAccessibilityTimePeriodConstraintList.isEmpty()) {
                     return false;
                  }

                  Collections.sort(filteredMonthlyAccessibilityTimePeriodConstraintList, (o1, o2) -> {
                     if (o1.getFromHour() < o2.getFromHour()) {
                        return -1;
                     } else if (o1.getFromHour() > o2.getFromHour()) {
                        return 1;
                     } else if (o1.getFromMinute() < o2.getFromMinute()) {
                        return -1;
                     } else {
                        return o1.getFromMinute() > o2.getFromMinute() ? 1 : 0;
                     }
                  });

                  for (int i = 0; i < filteredMonthlyAccessibilityTimePeriodConstraintList.size(); i++) {
                     MonthlyAccessibilityTimePeriodConstraint monthlyAccessibilityTimePeriodConstraint = filteredMonthlyAccessibilityTimePeriodConstraintList.get(
                        i
                     );
                     if (this.validateTimeConstraint(
                        monthlyAccessibilityTimePeriodConstraint.getFromHour(),
                        monthlyAccessibilityTimePeriodConstraint.getFromMinute(),
                        monthlyAccessibilityTimePeriodConstraint.getToHour(),
                        monthlyAccessibilityTimePeriodConstraint.getToMinute(),
                        now,
                        timezone
                     )) {
                        break;
                     }

                     if (i == filteredMonthlyAccessibilityTimePeriodConstraintList.size() - 1) {
                        return false;
                     }
                  }
            }
         }

         return true;
      }
   }

   public boolean validateTimeConstraint(int fromHour, int fromMinute, int toHour, int toMinute, ZonedDateTime now, String timezone) {
      ZonedDateTime startTime = ZonedDateTime.of(
         LocalDateTime.of(now.getYear(), now.getMonth(), now.getDayOfMonth(), fromHour, fromMinute, 0), ZoneId.of(timezone)
      );
      ZonedDateTime stopTime = ZonedDateTime.of(LocalDateTime.of(now.getYear(), now.getMonth(), now.getDayOfMonth(), toHour, toMinute, 0), ZoneId.of(timezone));
      long nowSeconds = now.toInstant().getEpochSecond();
      long stopTimeSeconds = stopTime.toInstant().getEpochSecond();
      if (nowSeconds >= startTime.toInstant().getEpochSecond() && nowSeconds <= stopTime.toInstant().getEpochSecond()) {
         this.initTerminateTask(stopTimeSeconds - nowSeconds - 1L);
         return true;
      } else {
         return false;
      }
   }

   private void initializeContexts(WebSocketSession session) {
      SecurityContextHolder.getContext().setAuthentication((Authentication)session.getPrincipal());
      RepositoryContextManager.openContext(this.entityManagerFactory);
      ThreadContext.put("user", session.getPrincipal().getName());
   }

   private void clearContexts() {
      SecurityContextHolder.clearContext();
      RepositoryContextManager.closeContext();
   }

   private void initTerminateTask(long delay) {
      this.asyncTaskExecutor.executeTask(new BridgeWebsocketSessionHandler.TerminationTask(), (int)delay, TimeUnit.SECONDS);
   }

   private void initializeSessionTimeout(Connection connection) {
      SessionTimeoutSetting sessionTimeoutSetting = this.sessionTimeoutSettingService.getRecord();
      switch (connection.getType()) {
         case SSH:
            this.sessionTimeoutThreshold = sessionTimeoutSetting.getSshConnectionTimeout();
            this.reactiveByMouseMovement = sessionTimeoutSetting.isReactiveSshByMouseMovement();
            break;
         case RDP:
            this.sessionTimeoutThreshold = sessionTimeoutSetting.getRdpConnectionTimeout();
            this.reactiveByMouseMovement = true;
            break;
         case VNC:
            this.sessionTimeoutThreshold = sessionTimeoutSetting.getVncConnectionTimeout();
            this.reactiveByMouseMovement = true;
            break;
         case TELNET:
            this.sessionTimeoutThreshold = sessionTimeoutSetting.getTelnetConnectionTimeout();
            this.reactiveByMouseMovement = sessionTimeoutSetting.isReactiveTelnetByMouseMovement();
      }

      this.sessionTimeoutThreshold *= 60;
      this.sessionLastActivityTime = Instant.now().getEpochSecond() + 3L;
   }

   private void registerSessionInputConstraintIncident(ManagedSession managedSession, String input, String regex) {
      SessionInputConstraintViolationIncident sessionInputConstraintViolationIncident = new SessionInputConstraintViolationIncident();
      sessionInputConstraintViolationIncident.setInput(input);
      sessionInputConstraintViolationIncident.setRegex(regex);
      sessionInputConstraintViolationIncident.setTime((long)Long.valueOf(Instant.now().getEpochSecond()).intValue());
      this.captureService.addNewSessionInputConstraintViolationIncident(sessionInputConstraintViolationIncident, managedSession);
   }

   private SessionInputConstraintViolationHandler generateBastionSessionInputConstraintHandler() {
      SessionInputConstraintViolationHandler handler = new SessionInputConstraintViolationHandler();
      SessionInputConstraint sessionInputConstraint = new SessionInputConstraint();
      sessionInputConstraint.setRegex("^[\\s|\\S]*[;|&]?\\s*(?:ssh|telnet).*");
      handler.setInputConstraint(sessionInputConstraint);
      handler.setPreventExecution(true);
      return handler;
   }

   private void submitExtractionTask(String content, InputSource source) {
      this.inputExtractionManager.submitNewTask(new RemoteSessionExtractionTaskRegistry(this.managedSession.getId(), content, source));
   }

   private class BridgeReader extends Thread {
      private final Lock SEND_MESSAGE_LOCK = new ReentrantLock();
      private final WebSocketSession webSocketSession;

      private BridgeReader(WebSocketSession webSocketSession, String sessionId) {
         this.webSocketSession = webSocketSession;
         this.setName(String.format("BRIDGE_READER_THREAD#%s", sessionId));
      }

      @Override
      public void run() {
         try {
            GuacamoleInstruction guacamoleInstruction = new GuacamoleInstruction(
               "sessionId", new String[]{BridgeWebsocketSessionHandler.this.managedSession.getId()}
            );
            this.webSocketSession.sendMessage(new TextMessage(guacamoleInstruction.toString()));
            int bufferSize = 8192;
            StringBuilder buffer = new StringBuilder(bufferSize);
            GuacamoleReader reader = BridgeWebsocketSessionHandler.this.managedSession.getTunnel().acquireReader();

            while (true) {
               char[] readMessage = reader.read();
               if (readMessage == null) {
                  break;
               }

               buffer.append(readMessage);
               if (!reader.available() || buffer.length() >= bufferSize) {
                  String message = buffer.toString();
                  this.sendContentsToClient(message);
                  BridgeWebsocketSessionHandler.this.submitExtractionTask(message, InputSource.SERVER);
                  buffer.setLength(0);
               }
            }
         } catch (GuacamoleConnectionClosedException var19) {
            BridgeWebsocketSessionHandler.LOGGER
               .debug(
                  Markers.SESSION,
                  "Connection to bridge is closed while reading next instruction for session '{}'. Connection is closed successfully",
                  BridgeWebsocketSessionHandler.this.managedSession.getId()
               );
         } catch (GuacamoleException var20) {
            BridgeWebsocketSessionHandler.LOGGER
               .error(
                  "An unexpected error occurred while reading bridge content for session with id '{}'",
                  BridgeWebsocketSessionHandler.this.managedSession.getId(),
                  var20
               );
            BridgeWebsocketSessionHandler.this.setCloseStatus(WebsocketSessionCloseStatus.BRIDGE_UNEXPECTED_ERROR);
         } catch (IOException var21) {
            BridgeWebsocketSessionHandler.this.setCloseStatus(WebsocketSessionCloseStatus.BRIDGE_IO_ERROR);
         } finally {
            BridgeWebsocketSessionHandler.this.bridgeConnectionClosed = true;
            BridgeWebsocketSessionHandler.this.managedSession.getTunnel().releaseReader();
            if (BridgeWebsocketSessionHandler.this.clientDisconnectReceived) {
               BridgeWebsocketSessionHandler.this.close(this.webSocketSession);
            } else {
               try {
                  this.webSocketSession.sendMessage(new TextMessage("10.disconnect;"));
               } catch (IOException var18) {
               }
            }
         }
      }

      private void sendContentsToClient(String message) {
         if (BridgeWebsocketSessionHandler.this.ocrRequestExecutor != null) {
            BridgeWebsocketSessionHandler.this.ocrRequestExecutor
               .registerRequest(new OcrRequest(BridgeWebsocketSessionHandler.this.managedSession.getId(), OcrRequestType.CAPTURE, message, null));
         }

         if (this.isDisconnectionInstruction(message)) {
            BridgeWebsocketSessionHandler.this.bridgeDisconnectReceived = true;
            if (BridgeWebsocketSessionHandler.this.clientDisconnectReceived) {
               this.sendNoOpToBridge();
            }
         }

         if (this.webSocketSession.isOpen() && !BridgeWebsocketSessionHandler.this.clientDisconnectReceived) {
            this.SEND_MESSAGE_LOCK.lock();

            try {
               this.webSocketSession.sendMessage(new TextMessage(message));
            } catch (Exception var9) {
               BridgeWebsocketSessionHandler.this.clientDisconnectReceived = true;
               if (!BridgeWebsocketSessionHandler.this.bridgeDisconnectReceived) {
                  try {
                     BridgeWebsocketSessionHandler.this.sendDisconnectInstructionToBridge();
                  } catch (GuacamoleException var8) {
                  }
               }
            } finally {
               this.SEND_MESSAGE_LOCK.unlock();
            }
         }
      }

      private boolean isDisconnectionInstruction(String instruction) {
         return instruction.contains(this.getDisconnectInstructionWithoutTerminator());
      }

      private String getDisconnectInstructionWithoutTerminator() {
         return "10.disconnect;".substring(0, "10.disconnect;".length() - 1);
      }

      private void sendNoOpToBridge() {
         try {
            GuacamoleWriter guacamoleWriter = BridgeWebsocketSessionHandler.this.managedSession.getTunnel().acquireWriter();
            guacamoleWriter.write("3.nop;".toCharArray());
            BridgeWebsocketSessionHandler.this.managedSession.getTunnel().releaseWriter();
         } catch (Exception var2) {
         }
      }
   }

   private class SendEmailTask implements Runnable {
      private final String violator;
      private final String recipient;
      private final String regex;
      private final String input;

      public SendEmailTask(String violator, String recipient, String regex, String input) {
         this.violator = violator;
         this.recipient = recipient;
         this.regex = regex;
         this.input = input;
      }

      @Override
      public void run() {
         try {
            BridgeWebsocketSessionHandler.this.emailSender
               .send(
                  this.recipient,
                  "Session Input Constraint Violation",
                  String.format("User '%s' violated a session input constraint. pattern: '%s', input: '%s'", this.violator, this.regex, this.input)
               );
         } catch (EmailSenderConfigurationNotRegisteredException var2) {
            BridgeWebsocketSessionHandler.LOGGER
               .warn(
                  Markers.SESSION,
                  "Email sender is not configured. Could not send email to {} for input constraint violation [regex: {}, input: {}]",
                  this.violator,
                  this.regex,
                  this.input
               );
         } catch (Exception var3) {
            BridgeWebsocketSessionHandler.LOGGER
               .error(
                  Markers.SESSION,
                  "An unexpected error occurred on sending email to {} for input constraint violation [regex: {}, input: {}]",
                  this.violator,
                  this.regex,
                  this.input,
                  var3
               );
         }
      }
   }

   private class SendSmsTask implements Runnable {
      private final String violator;
      private final String phoneNumber;
      private final String regex;
      private final String input;

      public SendSmsTask(String violator, String phoneNumber, String regex, String input) {
         this.violator = violator;
         this.phoneNumber = phoneNumber;
         this.regex = regex;
         this.input = input;
      }

      @Override
      public void run() {
         try {
            BridgeWebsocketSessionHandler.this.smsSender
               .send(
                  this.phoneNumber,
                  String.format("User '%s' violated a session input constraint. pattern: '%s', input: '%s'", this.violator, this.regex, this.input)
               );
         } catch (SmsSenderConfigurationNotRegisteredException var2) {
            BridgeWebsocketSessionHandler.LOGGER
               .warn(
                  "SMS sender is not configured. Failed to send SMS to '{}' on input constraint violation. input: {}, regex: {}",
                  this.phoneNumber,
                  this.input,
                  this.regex
               );
         } catch (Exception var3) {
            BridgeWebsocketSessionHandler.LOGGER
               .error(
                  "Unexpected error occurred while sending SMS to '{}' on input constraint violation. input: {}, regex: {}",
                  this.phoneNumber,
                  this.input,
                  this.regex,
                  var3
               );
         }
      }
   }

   private class TerminationTask implements Runnable {
      private TerminationTask() {
      }

      @Override
      public void run() {
         BridgeWebsocketSessionHandler.this.setCloseStatus(WebsocketSessionCloseStatus.TERMINATED_BY_ACCESSIBILITY_TIME_CONSTRAINT);
      }
   }
}
