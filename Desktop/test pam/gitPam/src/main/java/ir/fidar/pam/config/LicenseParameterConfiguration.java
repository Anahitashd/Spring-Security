package ir.fidar.pam.config;

import ir.fidar.core.da.repository.UserRepository;
import ir.fidar.core.license.register.LicenseParameter;
import ir.fidar.core.license.register.LicenseParameterConfigurer;
import ir.fidar.core.license.register.LicenseParameterRegistry;
import ir.fidar.pam.da.repository.BridgeRepository;
import ir.fidar.pam.da.repository.CaptureRepository;
import ir.fidar.pam.da.repository.connection.ConnectionRepository;
import ir.fidar.pam.service.impl.BridgeCrudServiceImpl;
import ir.fidar.pam.service.impl.connection.ConnectionCrudServiceImpl;
import ir.fidar.pam.service.impl.management.UserCrudServiceImpl;
import ir.fidar.pam.session.websocket.BridgeWebsocketSessionInitializationHandshakeInterceptor;
import org.springframework.stereotype.Component;

@Component
public class LicenseParameterConfiguration implements LicenseParameterConfigurer {
   private final UserRepository userRepository;
   private final ConnectionRepository connectionRepository;
   private final BridgeRepository bridgeRepository;
   private final CaptureRepository captureRepository;

   public LicenseParameterConfiguration(
      UserRepository userRepository, ConnectionRepository connectionRepository, BridgeRepository bridgeRepository, CaptureRepository captureRepository
   ) {
      this.userRepository = userRepository;
      this.connectionRepository = connectionRepository;
      this.bridgeRepository = bridgeRepository;
      this.captureRepository = captureRepository;
   }

   @Override
   public void registerParameter(LicenseParameterRegistry licenseParameterRegistry) {
      LicenseParameter userLicenseParameter = new LicenseParameter(
         "user", () -> Long.valueOf(this.userRepository.count()).intValue(), UserCrudServiceImpl.class
      );
      LicenseParameter ConnectionLicenseParameter = new LicenseParameter(
         "connection", () -> Long.valueOf(this.connectionRepository.count()).intValue(), ConnectionCrudServiceImpl.class
      );
      LicenseParameter bridgeLicenseParameter = new LicenseParameter(
         "bridge", () -> Long.valueOf(this.bridgeRepository.count()).intValue(), BridgeCrudServiceImpl.class
      );
      LicenseParameter concurrentSessionsLicenseParameter = new LicenseParameter(
         "session", () -> Long.valueOf(this.captureRepository.countLiveCaptures()).intValue(), BridgeWebsocketSessionInitializationHandshakeInterceptor.class
      );
      licenseParameterRegistry.register(userLicenseParameter, ConnectionLicenseParameter, bridgeLicenseParameter, concurrentSessionsLicenseParameter);
   }
}
