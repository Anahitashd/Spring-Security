package ir.fidar.pam.service.impl;

import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.pam.da.repository.CaptureRepository;
import ir.fidar.pam.da.repository.SessionInputConstraintViolationIncidentRepository;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.CaptureClientInformation;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.model.session.SessionTransferredFile;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.CaptureExecutedCommandService;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.service.CaptureTransferredClipboardService;
import ir.fidar.pam.session.ManagedSession;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CaptureServiceImpl implements CaptureService {
   private static final Logger LOGGER = LogManager.getLogger();
   private final CaptureRepository captureRepository;
   private final SessionInputConstraintViolationIncidentRepository inputConstraintViolationIncidentRepository;
   private final CaptureTransferredClipboardService captureTransferredClipboardService;
   private final CaptureExecutedCommandService captureExecutedCommandService;

   public CaptureServiceImpl(
      CaptureRepository captureRepository,
      SessionInputConstraintViolationIncidentRepository inputConstraintViolationIncidentRepository,
      CaptureTransferredClipboardService captureTransferredClipboardService,
      CaptureExecutedCommandService captureExecutedCommandService
   ) {
      this.captureRepository = captureRepository;
      this.inputConstraintViolationIncidentRepository = inputConstraintViolationIncidentRepository;
      this.captureTransferredClipboardService = captureTransferredClipboardService;
      this.captureExecutedCommandService = captureExecutedCommandService;
   }

   @Override
   public Capture getBySessionId(String sessionId) {
      return this.captureRepository.findOneBySessionId(sessionId);
   }

   @Transactional
   @Override
   public void create(ManagedSession managedSession) {
      Capture capture = new Capture();
      capture.setSessionId(managedSession.getId());
      capture.setAccessRuleUuid(managedSession.getAccessRule().getUuid());
      capture.setOwner(managedSession.getUser());
      capture.setType(managedSession.getConnection().getType());
      capture.setConnectionIpAddress(managedSession.getConnection().getIpAddress());
      capture.setConnectionName(managedSession.getConnection().getName());
      capture.setConnectionPort(managedSession.getConnection().getPort());
      capture.setBridgeName(managedSession.getAccessRule().getBridge().getName());
      capture.setBridgeIpAddress(managedSession.getAccessRule().getBridge().getIpAddress());
      capture.setActiveFileTransferMode(managedSession.getAccessRule().getFileTransferMode());
      capture.setHadClipboard(managedSession.getAccessRule().isClipboard());
      if (managedSession.getAccessRuleConnection().getCredential().getLabel().equalsIgnoreCase("onfly")) {
         capture.setCredentialLabel(null);
      } else {
         capture.setCredentialLabel(managedSession.getAccessRuleConnection().getCredential().getLabel());
      }

      CaptureClientInformation clientInformation = new CaptureClientInformation();
      clientInformation.setCapture(capture);
      clientInformation.setScreenWidth(Integer.valueOf(managedSession.getClientInformation().getOptimalScreenWidth()).shortValue());
      clientInformation.setScreenHeight(Integer.valueOf(managedSession.getClientInformation().getOptimalScreenHeight()).shortValue());
      clientInformation.setScreenDpi(Integer.valueOf(managedSession.getClientInformation().getOptimalResolution()).shortValue());
      capture.setClientInformation(clientInformation);
      this.setTimesAndStatus(capture, managedSession);
      LOGGER.debug(
         Markers.SESSION,
         "New capture is persisted to database for '{}' session '{}' to connection '{}' through access-rule '{}'",
         capture.getType(),
         capture.getSessionId(),
         capture.getConnectionName(),
         managedSession.getAccessRule().getName()
      );
      this.captureRepository.save(capture);
   }

   @Override
   public void addNewSessionInputConstraintViolationIncident(
      SessionInputConstraintViolationIncident sessionInputConstraintViolationIncident, ManagedSession managedSession
   ) {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(managedSession.getId()))
         .orElseThrow(() -> new SystemInternalErrorException(new EntityNotFoundException(Capture.class)));
      sessionInputConstraintViolationIncident.setCapture(capture);
      this.inputConstraintViolationIncidentRepository.save(sessionInputConstraintViolationIncident);
   }

   @Transactional
   @Override
   public void updateSessionTransferredFiles(SessionTransferredFile sessionTransferredFile, ManagedSession managedSession) {
      if (managedSession != null) {
         Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(managedSession.getId()))
            .orElseThrow(() -> new SystemInternalErrorException(new EntityNotFoundException(Capture.class)));
         sessionTransferredFile.setCapture(capture);
         capture.getSessionTransferredFiles().add(sessionTransferredFile);
      }
   }

   @Transactional
   @Override
   public void close(ManagedSession managedSession) {
      LOGGER.debug(
         Markers.SESSION,
         "About to set capture's status to 'CLOSED' for session '{}'. Managed session status: {}",
         managedSession.getId(),
         managedSession.getStatus().toString()
      );
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(managedSession.getId()))
         .orElseThrow(() -> new SystemInternalErrorException(new EntityNotFoundException(Capture.class)));
      capture.setStatus(CaptureStatus.CLOSED);
      capture.setEndTime(managedSession.getStopTime());
      this.captureRepository.save(capture);
      LOGGER.debug(
         Markers.SESSION,
         "Capture status is set to '{}' for {} session '{}' to '{}' connection through '{}' access rule",
         CaptureStatus.CLOSED.toString(),
         capture.getType(),
         capture.getSessionId(),
         capture.getConnectionName(),
         managedSession.getAccessRule().getName()
      );
   }

   @Override
   public boolean isSessionIdAlreadyRegistered(String sessionId) {
      return this.captureRepository.existsBySessionId(sessionId);
   }

   @Override
   public void syncCaptureAndSessionStatus(Set<String> liveSessionIds) {
      this.captureRepository.syncCaptureAndSessionStatus(liveSessionIds);
   }

   @Transactional
   @Override
   public void saveCapture(Capture capture) {
      this.captureRepository.save(capture);
   }

   @Override
   public boolean existAnyCapturedVideoForConnection(String connectionName) {
      return this.captureRepository.existsByConnectionNameIgnoreCase(connectionName);
   }

   @Override
   public void addTransferredClipboard(String sessionId, CaptureTransferredClipboard captureTransferredClipboard) {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new SystemInternalErrorException(new EntityNotFoundException(Capture.class)));
      captureTransferredClipboard.setCapture(capture);
      this.captureTransferredClipboardService.create(captureTransferredClipboard);
   }

   @Override
   public void addExecutedCommand(String sessionId, CaptureExecutedCommand captureExecutedCommand) {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new SystemInternalErrorException(new EntityNotFoundException(Capture.class)));
      captureExecutedCommand.setCapture(capture);
      this.captureExecutedCommandService.create(captureExecutedCommand);
   }

   private void setTimesAndStatus(Capture capture, ManagedSession managedSession) {
      switch (managedSession.getStatus()) {
         case OPEN:
            capture.setStartTime(managedSession.getStartTime());
            capture.setEndTime(0L);
            capture.setStatus(CaptureStatus.LIVE);
            break;
         case CLOSE:
            capture.setEndTime(managedSession.getStopTime());
            if (capture.getEndTime() == 0L) {
               capture.setEndTime(Instant.now().getEpochSecond());
            }

            capture.setStatus(CaptureStatus.CLOSED);
      }
   }
}
