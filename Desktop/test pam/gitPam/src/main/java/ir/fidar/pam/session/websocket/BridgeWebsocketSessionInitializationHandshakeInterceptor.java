package ir.fidar.pam.session.websocket;

import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.license.register.LicenseInterceptingPoint;
import ir.fidar.core.security.service.AuthorizationService;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.AccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodRepository;
import ir.fidar.pam.domain.dto.connection.ConnectionSessionInteractionModeDto;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import ir.fidar.pam.domain.type.CredentialType;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.connection.ConnectionService;
import ir.fidar.pam.session.SessionManager;
import ir.fidar.pam.session.exception.CredentialNotFoundException;
import ir.fidar.pam.session.exception.DisabledAccessRuleException;
import ir.fidar.pam.session.exception.ExpiredAccessRuleException;
import ir.fidar.pam.session.exception.InvalidSessionRequestParametersException;
import ir.fidar.pam.session.exception.MaximumConcurrentSessionsExeecedException;
import ir.fidar.pam.session.exception.MaximumConcurrentSessionsPerUserExeecedException;
import ir.fidar.pam.session.exception.SessionNotFountException;
import ir.fidar.pam.session.exception.SessionRequestException;
import ir.fidar.pam.session.exception.UnauthorizedUserException;
import ir.fidar.pam.session.exception.UnsupportedSubProtocolException;
import java.time.Instant;
import java.util.*;
import javax.servlet.http.HttpServletRequest;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.HandshakeInterceptor;

@Component
public class BridgeWebsocketSessionInitializationHandshakeInterceptor implements HandshakeInterceptor {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String REMEMBER_ME_CODE = "USER_RM_CRED";
   private final AuthorizationService authorizationService;
   private final ConnectionService connectionService;
   private final AccessRuleService accessRuleService;
   private final NativeQueryBasedReadRepository nativeQueryBasedReadRepository;
   private final JpaQueryBasedReadRepository jpaQueryBasedReadRepository;
   private final RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager;
   private final AccessibilityTimePeriodConstraintRepository accessibilityTimePeriodConstraintRepository;
   private final WeeklyAccessibilityTimePeriodRepository weeklyAccessibilityTimePeriodRepository;
   private final MonthlyAccessibilityTimePeriodConstraintRepository monthlyAccessibilityTimePeriodConstraintRepository;

   public BridgeWebsocketSessionInitializationHandshakeInterceptor(
           AuthorizationService authorizationService,
           ConnectionService connectionService,
           AccessRuleService accessRuleService,
           NativeQueryBasedReadRepository nativeQueryBasedReadRepository,
           JpaQueryBasedReadRepository jpaQueryBasedReadRepository,
           RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager,
           AccessibilityTimePeriodConstraintRepository accessibilityTimePeriodConstraintRepository,
           WeeklyAccessibilityTimePeriodRepository weeklyAccessibilityTimePeriodRepository,
           MonthlyAccessibilityTimePeriodConstraintRepository monthlyAccessibilityTimePeriodConstraintRepository
   ) {
      this.authorizationService = authorizationService;
      this.connectionService = connectionService;
      this.accessRuleService = accessRuleService;
      this.nativeQueryBasedReadRepository = nativeQueryBasedReadRepository;
      this.jpaQueryBasedReadRepository = jpaQueryBasedReadRepository;
      this.remoteSessionUserCredentialStorageManager = remoteSessionUserCredentialStorageManager;
      this.accessibilityTimePeriodConstraintRepository = accessibilityTimePeriodConstraintRepository;
      this.weeklyAccessibilityTimePeriodRepository = weeklyAccessibilityTimePeriodRepository;
      this.monthlyAccessibilityTimePeriodConstraintRepository = monthlyAccessibilityTimePeriodConstraintRepository;
   }

   @LicenseInterceptingPoint
   @Transactional(
      readOnly = true
   )
   public boolean beforeHandshake(
      ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse, WebSocketHandler webSocketHandler, Map<String, Object> attributes
   ) {
      String requestUri = serverHttpRequest.getURI().getPath();
      if (requestUri.startsWith("/")) {
         requestUri = requestUri.substring(1);
      }

      String[] parts = StringUtils.split(requestUri, "/");
      String accessRuleUUID = parts[parts.length - 2];
      String connectionName = parts[parts.length - 1];
      LOGGER.debug(Markers.SESSION, "About to processing session request for access-rule '{}' and connection '{}'", accessRuleUUID, connectionName);

      try {
         AccessRuleConnection accessRuleConnection = this.fetchAccessRuleByUuidWithRequiredAssociations(accessRuleUUID, connectionName);
         AccessRule accessRule = accessRuleConnection.getAccessRule();
         attributes.put(WebsocketSessionAttributeKey.UNDERLYING_ACCESS_RULE.toString(), accessRuleConnection);
         LOGGER.debug(
            Markers.SESSION,
            "Access-Rule's info is fetched successfully. name: {}, connection name: {}, connection type: {}",
            accessRule.getName(),
            accessRuleConnection.getConnection().getName(),
            accessRuleConnection.getConnection().getType()
         );
         if (accessRule.isDisabled()) {
            throw new DisabledAccessRuleException(WebsocketSessionCloseStatus.DISABLED_ACCESS_RULE);
         } else if (accessRule.getExpirationTime() > 0L && accessRule.getExpirationTime() <= Instant.now().getEpochSecond()) {
            throw new ExpiredAccessRuleException(WebsocketSessionCloseStatus.EXPIRED_ACCESS_RULE);
         } else {
            List<AccessibilityTimePeriodConstraint> accessibilityTimePeriodConstraints = this.fetchAccessibilityTimePeriodConstraints(accessRuleConnection);
            if (!accessibilityTimePeriodConstraints.isEmpty()) {
               attributes.put(WebsocketSessionAttributeKey.ACCESSIBILITY_TIME_CONSTRAINT.toString(), accessibilityTimePeriodConstraints);
            }

            attributes.put(WebsocketSessionAttributeKey.CLIENT_INFORMATION.toString(), this.retrieveSessionRequestParameters(serverHttpRequest));
            Map<BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter, String> subProtocolHeaderValues = this.retrieveSubProtocolHeaderValues(
               serverHttpRequest
            );
            this.validateProtocol(subProtocolHeaderValues.get(BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter.SUB_PROTOCOL));
            this.validateAccessRuleAssignedCredential(
               accessRuleConnection, subProtocolHeaderValues.get(BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter.CREDENTIAL)
            );
            this.validateConcurrentSessionsLimitation(accessRuleConnection.getConnection());
            return true;
         }
      } catch (SessionRequestException var13) {
         attributes.put(WebsocketSessionAttributeKey.CLOSE_STATUS.toString(), var13.getCloseStatus());
         return true;
      } catch (Exception var14) {
         LOGGER.error(Markers.SESSION, "Unexpected error occurred while processing session request for access-rule '{}'", accessRuleUUID, var14);
         serverHttpResponse.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
         return false;
      }
   }

   public void afterHandshake(ServerHttpRequest serverHttpRequest, ServerHttpResponse serverHttpResponse, WebSocketHandler webSocketHandler, Exception e) {
      serverHttpResponse.getHeaders().add("Sec-Websocket-Protocol", "fidar-pam");
   }

   private AccessRuleConnection fetchAccessRuleByUuidWithRequiredAssociations(String uuid, String connectionName) throws SessionNotFountException, UnauthorizedUserException {
      long userId = this.authorizationService.getCurrentUserInfo().getId();
      Connection connection = this.connectionService.getOne(connectionName);
      AccessRule accessRule = this.accessRuleService.getOneByUserAndConnection(userId, connection.getId());
      if (accessRule != null && accessRule.getUuid().equalsIgnoreCase(uuid)) {
         AccessRuleConnection accessRuleConnection = Optional.ofNullable(this.accessRuleService.getConnectionSettings(accessRule.getId(), connection.getId()))
            .orElse(new AccessRuleConnection());
         if (accessRuleConnection.getCredential() != null) {
            accessRuleConnection.setCredential(this.connectionService.getTypedCredential(accessRuleConnection.getCredential()));
         }

         if (accessRuleConnection.getRdpConnectionRemoteApplication() != null) {
            RdpConnectionRemoteApplication rdpConnectionRemoteApplication = new RdpConnectionRemoteApplication();
            rdpConnectionRemoteApplication.setName(accessRuleConnection.getRdpConnectionRemoteApplication().getName());
            rdpConnectionRemoteApplication.setParams(accessRuleConnection.getRdpConnectionRemoteApplication().getParams());
            rdpConnectionRemoteApplication.setWorkingDirectory(accessRuleConnection.getRdpConnectionRemoteApplication().getWorkingDirectory());
            accessRuleConnection.setRdpConnectionRemoteApplication(rdpConnectionRemoteApplication);
         }

         List<FilterChain> idFilter = QueryAndFilterUtils.idFilter(accessRule.getId());
         NativeQuery query = new NativeQueryBuilder().from(Bridge.class, "b").join(AccessRule.class, "ar").on("id", "bridge_id").joinWhere(idFilter).build();
         Bridge bridge = (Bridge)this.nativeQueryBasedReadRepository.findOne(query);
         JpaQuery<SessionInputConstraintViolationHandler> jpaQuery = new JpaQueryBuilder()
            .from(SessionInputConstraintViolationHandler.class, "sich")
            .distinct()
            .join("inputConstraint", "ic")
            .fetch()
            .where(
               new FilterChainBuilder()
                  .filter(new FilterBuilder().number("accessRule.id").eq(accessRule.getId()).or().number("connection.id").eq(connection.getId()).build())
                  .build()
            )
            .build();
         List<SessionInputConstraintViolationHandler> sessionInputConstraintViolationHandlers = this.jpaQueryBasedReadRepository.findAll(jpaQuery);
         ConnectionSessionInteractionModeDto interactionModeDto = this.accessRuleService.resolveInteractionSettings(accessRule, connection);
         accessRule.setClipboard(interactionModeDto.isClipboard());
         accessRule.setBastion(interactionModeDto.isBastion());
         accessRule.setFileTransferMode(interactionModeDto.getFileTransferMode());
         accessRule.setBridge(bridge);
         accessRule.setSessionInputConstraints(new HashSet<>(sessionInputConstraintViolationHandlers));
         accessRuleConnection.setAccessRule(accessRule);
         accessRuleConnection.setConnection(connection);
         return accessRuleConnection;
      } else {
         throw new UnauthorizedUserException(WebsocketSessionCloseStatus.UNAUTHORIZED_USER);
      }
   }

//   private List<AccessibilityTimePeriodConstraint> fetchAccessibilityTimePeriodConstraints(AccessRuleConnection accessRuleConnection) {
//      NativeQuery<AccessibilityTimePeriodConstraint> fetchAccessibilityTimePeriodConstraintQuery = new NativeQueryBuilder()
//         .from(AccessibilityTimePeriodConstraint.class, "a")
//         .where(
//            new FilterChainBuilder()
//               .filter(
//                  new FilterBuilder()
//                     .number("access_rule_id")
//                     .eq(accessRuleConnection.getAccessRule().getId())
//                     .or()
//                     .number("connection_id")
//                     .eq(accessRuleConnection.getConnection().getId())
//                     .build()
//               )
//               .build()
//         )
//         .build();
//      List<AccessibilityTimePeriodConstraint> accessibilityTimePeriodConstraints = this.nativeQueryBasedReadRepository
//         .findAll(fetchAccessibilityTimePeriodConstraintQuery);
//
//      for (AccessibilityTimePeriodConstraint accessibilityTimePeriodConstraint : accessibilityTimePeriodConstraints) {
//         if (!accessibilityTimePeriodConstraint.getMode().equals(AccessibilityTimePeriodMode.DAILY)) {
//            if (accessibilityTimePeriodConstraint.getMode().equals(AccessibilityTimePeriodMode.WEEKLY)) {
//               accessibilityTimePeriodConstraint.getWeeklyConstraints().size();
//            } else {
//               accessibilityTimePeriodConstraint.getMonthlyConstraints().size();
//            }
//         }
//      }
//
//      return accessibilityTimePeriodConstraints;
//   }


   private List<AccessibilityTimePeriodConstraint> fetchAccessibilityTimePeriodConstraints(AccessRuleConnection accessRuleConnection) {
      Long connectionId = Objects.nonNull(accessRuleConnection.getConnection()) ? accessRuleConnection.getConnection().getId() : null;
      Long accessRuleId = Objects.nonNull(accessRuleConnection.getAccessRule()) ? accessRuleConnection.getAccessRule().getId() : null;
      List<AccessibilityTimePeriodConstraint> constraints = accessibilityTimePeriodConstraintRepository
              .fetchAccessibilityTimePeriodConstraints(accessRuleId,
                      connectionId);

      if (Objects.nonNull(constraints))
         constraints.forEach(atpc -> {
            atpc.setWeeklyConstraints(weeklyAccessibilityTimePeriodRepository.findByTimePeriodConstraintId(atpc.getId()));
            atpc.setMonthlyConstraints(monthlyAccessibilityTimePeriodConstraintRepository.findByTimePeriodConstraintId(atpc.getId()));
         });

      return constraints;
   }



   private GuacamoleClientInformation retrieveSessionRequestParameters(ServerHttpRequest serverHttpRequest) throws InvalidSessionRequestParametersException {
      HttpServletRequest request = ((ServletServerHttpRequest)serverHttpRequest).getServletRequest();
      GuacamoleClientInformation guacamoleClientInformation = new GuacamoleClientInformation();
      int screenWidth = Integer.parseInt(request.getParameter("WIDTH"));
      int screenHeight = Integer.parseInt(request.getParameter("HEIGHT"));
      int screenDPI = Integer.parseInt(request.getParameter("DPI"));
      String[] supportedImageTypes = request.getParameterValues("IMAGE");
      if (screenWidth > 0 && screenHeight > 0 && screenDPI > 0 && supportedImageTypes != null && supportedImageTypes.length != 0) {
         guacamoleClientInformation.setOptimalScreenWidth(screenWidth);
         guacamoleClientInformation.setOptimalScreenHeight(screenHeight);
         guacamoleClientInformation.setOptimalResolution(screenDPI);
         guacamoleClientInformation.getImageMimetypes().addAll(Arrays.asList(supportedImageTypes));
         String[] supportedAudioTypes = request.getParameterValues("AUDIO");
         if (supportedAudioTypes != null && supportedAudioTypes.length != 0) {
            guacamoleClientInformation.getAudioMimetypes().addAll(Arrays.asList(supportedAudioTypes));
         }

         String[] supportedVideoTypes = request.getParameterValues("VIDEO");
         if (supportedVideoTypes != null && supportedVideoTypes.length != 0) {
            guacamoleClientInformation.getVideoMimetypes().addAll(Arrays.asList(supportedVideoTypes));
         }

         return guacamoleClientInformation;
      } else {
         throw new InvalidSessionRequestParametersException(WebsocketSessionCloseStatus.INVALID_REQUEST_PARAMETERS);
      }
   }

   private Map<BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter, String> retrieveSubProtocolHeaderValues(ServerHttpRequest serverHttpRequest) {
      List<String> values = serverHttpRequest.getHeaders().get("Sec-Websocket-Protocol");
      String[] temp = values.get(0).split(",");
      Map<BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter, String> result = new HashMap<>();
      result.put(BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter.SUB_PROTOCOL, temp[0].trim());
      if (temp.length > 1) {
         result.put(BridgeWebsocketSessionInitializationHandshakeInterceptor.Parameter.CREDENTIAL, temp[1].trim());
      }

      return result;
   }

   private void validateProtocol(String providedProtocol) throws UnsupportedSubProtocolException {
      if (!providedProtocol.equalsIgnoreCase("fidar-pam")) {
         throw new UnsupportedSubProtocolException(WebsocketSessionCloseStatus.UNSUPPORTED_SUB_PROTOCOL);
      }
   }

   private void validateAccessRuleAssignedCredential(AccessRuleConnection accessRuleConnection, String providedCredential) throws CredentialNotFoundException {
      try {
         if (accessRuleConnection.getCredential() == null) {
            LOGGER.debug(
               Markers.SESSION,
               "Access-Rule '{}' does not have any credential. About to set OnFly credential set to request header",
               accessRuleConnection.getAccessRule().getName()
            );
            UsernamePasswordCredential usernamePasswordCredential;
            if (!StringUtils.hasContent(providedCredential)) {
               usernamePasswordCredential = this.remoteSessionUserCredentialStorageManager
                  .getCredential(this.authorizationService.getCurrentUserInfo().getUsername(), accessRuleConnection.getConnection());
            } else {
               String decodedCredential = new String(Base64.getDecoder().decode(providedCredential));
               int passwordStartIndex = decodedCredential.indexOf(":");
               int passwordLastIndex = decodedCredential.lastIndexOf(":");
               String username = decodedCredential.substring(0, passwordStartIndex);
               boolean rememberMe = false;
               String password;
               if (passwordLastIndex == passwordStartIndex) {
                  password = decodedCredential.substring(passwordStartIndex + 1);
               } else {
                  password = decodedCredential.substring(passwordStartIndex + 1, passwordLastIndex);
                  rememberMe = decodedCredential.substring(passwordLastIndex + 1).equalsIgnoreCase(Boolean.TRUE.toString());
               }

               usernamePasswordCredential = new UsernamePasswordCredential();
               usernamePasswordCredential.setLabel("OnFly");
               usernamePasswordCredential.setType(CredentialType.USERNAME_PASSWORD);
               usernamePasswordCredential.setUsername(username);
               usernamePasswordCredential.setPassword(password);
               if (rememberMe) {
                  this.remoteSessionUserCredentialStorageManager
                     .save(this.authorizationService.getCurrentUserInfo().getUsername(), accessRuleConnection.getConnection(), usernamePasswordCredential);
               } else {
                  this.remoteSessionUserCredentialStorageManager
                     .delete(this.authorizationService.getCurrentUserInfo().getUsername(), accessRuleConnection.getConnection());
               }
            }

            if (usernamePasswordCredential == null) {
               throw new CredentialNotFoundException(WebsocketSessionCloseStatus.CREDENTIAL_NOT_FOUND);
            }

            accessRuleConnection.setCredential(usernamePasswordCredential);
         }
      } catch (Exception var10) {
         var10.printStackTrace();
         throw var10;
      }
   }

   private void validateConcurrentSessionsLimitation(Connection connection) throws MaximumConcurrentSessionsExeecedException, MaximumConcurrentSessionsPerUserExeecedException {
      SessionManager.SessionNumber sessionNumber = SessionManager.getNumberOfSessionsOverSpecificConnection(
         connection.getName(), this.authorizationService.getCurrentUserInfo().getUsername()
      );
      if (connection.getMaximumConcurrentSessions() > 0
         && connection.getMaximumConcurrentSessions() <= sessionNumber.getNumberOfSessionsOverSpecificConnection()) {
         throw new MaximumConcurrentSessionsExeecedException(WebsocketSessionCloseStatus.EXCEEDED_MAX_CONCURRENT_SESSIONS);
      } else if (connection.getMaximumConcurrentSessionsPerUser() > 0
         && connection.getMaximumConcurrentSessionsPerUser() <= sessionNumber.getNumberOfSessionsOverSpecificConnectionEstablishedBySpecificUser()) {
         throw new MaximumConcurrentSessionsPerUserExeecedException(WebsocketSessionCloseStatus.EXCEEDED_MAX_CONCURRENT_SESSIONS_PER_USER);
      }
   }

   private static enum Parameter {
      SUB_PROTOCOL,
      CREDENTIAL;
   }
}
