package ir.fidar.pam.session;

import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.security.context.ApplicationStartupInitializer;
import ir.fidar.pam.da.repository.CaptureRepository;
import ir.fidar.pam.domain.model.SessionTimeoutSetting;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.service.SessionTimeoutSettingService;
import ir.fidar.pam.session.websocket.BridgeWebsocketSessionHandler;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Component;

@Component
public class SessionManagementApplicationStartupInitializer implements ApplicationStartupInitializer {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final long SESSION_END_TIME_PASSED_THRESHOLD_SECONDS = 30L;
   private final CaptureRepository captureRepository;
   private final CaptureService captureService;
   private final SessionTimeoutSettingService sessionTimeoutSettingService;
   private final AsyncTaskExecutor asyncTaskExecutor;

   public SessionManagementApplicationStartupInitializer(
      CaptureRepository captureRepository,
      CaptureService captureService,
      SessionTimeoutSettingService sessionTimeoutSettingService,
      AsyncTaskExecutor asyncTaskExecutor
   ) {
      this.captureRepository = captureRepository;
      this.captureService = captureService;
      this.sessionTimeoutSettingService = sessionTimeoutSettingService;
      this.asyncTaskExecutor = asyncTaskExecutor;
   }

   @Override
   public void initialize() {
      this.captureRepository.closeAllOpenCaptures();
      LOGGER.debug(Markers.SESSION, "Open sessions from last startup are closed");
      SessionTimeoutSetting sessionTimeoutSetting = new SessionTimeoutSetting();
      sessionTimeoutSetting.setReactiveSshByMouseMovement(false);
      sessionTimeoutSetting.setReactiveTelnetByMouseMovement(false);
      sessionTimeoutSetting.setSshConnectionTimeout(15);
      sessionTimeoutSetting.setRdpConnectionTimeout(15);
      sessionTimeoutSetting.setVncConnectionTimeout(15);
      sessionTimeoutSetting.setTelnetConnectionTimeout(15);
      this.sessionTimeoutSettingService.register(sessionTimeoutSetting, false);
      this.asyncTaskExecutor.executeTask(new SessionManagementApplicationStartupInitializer.SessionAndTableStatusSynchronizationTask(), 1, 1, TimeUnit.MINUTES);
   }

   private class SessionAndTableStatusSynchronizationTask implements Runnable {
      private byte counter = 1;

      private SessionAndTableStatusSynchronizationTask() {
      }

      @Override
      public void run() {
         Set<Session> sessions = SessionManager.getAllSessions();
         SessionManagementApplicationStartupInitializer.this.captureService
            .syncCaptureAndSessionStatus(sessions.stream().map(Session::getId).collect(Collectors.toSet()));
         long now = Instant.now().getEpochSecond();

         for (Session session : sessions) {
            ManagedSession managedSession = (ManagedSession)session;
            if (!((BridgeWebsocketSessionHandler)managedSession.getWebsocketHandler()).isAlive()) {
               if (managedSession.getStopTime() != 0L) {
                  if (now - managedSession.getStopTime() >= 30L) {
                     SessionManagementApplicationStartupInitializer.this.captureService.close(managedSession);
                     SessionManager.terminateSessionSoftly(managedSession.getId());
                  }
               } else {
                  SessionManagementApplicationStartupInitializer.this.asyncTaskExecutor.executeTask(() -> {
                     SessionManagementApplicationStartupInitializer.this.captureService.close(managedSession);
                     SessionManager.terminateSessionSoftly(managedSession.getId());
                  }, 30, TimeUnit.SECONDS);
               }
            }
         }

         if (this.counter == 10) {
            SessionManagementApplicationStartupInitializer.LOGGER.debug(Markers.SESSION, "Captures and sessions status is synchronized");
            this.counter = 1;
         } else {
            this.counter++;
         }
      }
   }
}
