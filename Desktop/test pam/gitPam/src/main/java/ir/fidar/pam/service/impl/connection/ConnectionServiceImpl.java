package ir.fidar.pam.service.impl.connection;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.da.repository.CredentialRepository;
import ir.fidar.pam.da.repository.RdpConnectionRemoteApplicationRepository;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.AccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodRepository;
import ir.fidar.pam.da.repository.connection.ConnectionRepository;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.RdpConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.SshConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.TelnetConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.VncConnectionCreateDto;
import ir.fidar.pam.domain.dto.credential.create.CredentialCreateDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.RdpConnection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.connection.SshConnection;
import ir.fidar.pam.domain.model.connection.TelnetConnection;
import ir.fidar.pam.domain.model.connection.VncConnection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.type.ColorDepth;
import ir.fidar.pam.domain.type.ColorScheme;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.type.RdpConnectionSecurityMode;
import ir.fidar.pam.domain.type.VncConnectionClipboardEncoding;
import ir.fidar.pam.domain.type.VncConnectionCursorMode;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.CaptureRuleService;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.service.KavoshIntegrationService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

@Service
public class ConnectionServiceImpl extends ConnectionCrudServiceImpl implements ConnectionService {
   private final ConnectionRepository connectionRepository;
   private final JpaQueryBasedReadRepository readRepository;
   private final AccessRuleService accessRuleService;
   private final CredentialRepository credentialRepository;

   public ConnectionServiceImpl(
      ConnectionRepository connectionRepository,
      GenericCrudRepository<SshConnection> sshConnectionCrudRepository,
      GenericCrudRepository<RdpConnection> rdpConnectionCrudRepository,
      GenericCrudRepository<VncConnection> vncConnectionCrudRepository,
      GenericCrudRepository<TelnetConnection> telnetConnectionCrudRepository,
      JpaQueryBasedReadRepository jpaQueryBasedReadRepository,
      NativeQueryBasedReadRepository genericNativeQueryBasedReadRepository,
      SessionInputConstraintRepository sessionInputConstraintRepository,
      AccessibilityTimePeriodConstraintRepository accessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<AccessibilityTimePeriodConstraint> timePeriodConstraintCrudRepository,
      DailyAccessibilityTimePeriodConstraintRepository dailyAccessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<DailyAccessibilityTimePeriodConstraint> dailyAccessibilityTimePeriodConstraintCrudRepository,
      WeeklyAccessibilityTimePeriodRepository weeklyAccessibilityTimePeriodRepository,
      GenericCrudRepository<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraintCrudRepository,
      MonthlyAccessibilityTimePeriodConstraintRepository monthlyAccessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraintCrudRepository,
      GenericCrudRepository<SessionInputConstraintViolationHandler> sessionInputConstraintViolationHandlerCrudRepository,
      GenericCrudRepository<Banner> bannerCrudRepository,
      RdpConnectionRemoteApplicationRepository rdpConnectionRemoteApplicationRepository,
      @Lazy CredentialRepository credentialRepository,
      GenericCrudRepository<RdpConnectionRemoteApplication> rdpRemoteApplicationCrudRepository,
      GenericCrudRepository<Credential> credentialCrudRepository,
      GenericCrudRepository<CaptureRule> captureRuleCrudRepository,
      CaptureService captureService,
      KavoshIntegrationService kavoshIntegrationService,
      JpaQueryBasedReadRepository readRepository,
      @Lazy AccessRuleService accessRuleService
   ) {
      super(
         connectionRepository,
         sshConnectionCrudRepository,
         rdpConnectionCrudRepository,
         vncConnectionCrudRepository,
         telnetConnectionCrudRepository,
         jpaQueryBasedReadRepository,
         genericNativeQueryBasedReadRepository,
         sessionInputConstraintRepository,
         accessibilityTimePeriodConstraintRepository,
         timePeriodConstraintCrudRepository,
         dailyAccessibilityTimePeriodConstraintRepository,
         dailyAccessibilityTimePeriodConstraintCrudRepository,
         weeklyAccessibilityTimePeriodRepository,
         weeklyAccessibilityTimePeriodConstraintCrudRepository,
         monthlyAccessibilityTimePeriodConstraintRepository,
         monthlyAccessibilityTimePeriodConstraintCrudRepository,
         sessionInputConstraintViolationHandlerCrudRepository,
         bannerCrudRepository,
         rdpConnectionRemoteApplicationRepository,
         credentialRepository,
         credentialCrudRepository,
         rdpRemoteApplicationCrudRepository,
         captureRuleCrudRepository,
         captureService,
         kavoshIntegrationService,
         accessRuleService
      );
      this.connectionRepository = connectionRepository;
      this.readRepository = readRepository;
      this.accessRuleService = accessRuleService;
      this.credentialRepository = credentialRepository;
   }

   @Override
   public void setCaptureRuleService(CaptureRuleService captureRuleService) {
      super.setCaptureRuleService(captureRuleService);
   }

   @Override
   public List<Connection> getAll() {
      return this.connectionRepository.findAll();
   }

   public Connection getOne(String name) {
      return Optional.ofNullable(this.connectionRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
   }

   public Connection getOne(Long id) {
      return Optional.ofNullable(this.connectionRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
   }

   @Override
   public Connection getOne(String name, boolean readOnly) {
      JpaQuery<Connection> fetchByTitleQuery = new JpaQueryBuilder()
         .from(Connection.class, "c")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      return Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchByTitleQuery, readOnly))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
   }

   @Override
   public void createNewRecord(
      String name,
      ConnectionType type,
      String ipAddress,
      int port,
      boolean clipboardEnabled,
      FileTransferMode fileTransferMode,
      CredentialCreateDto credential,
      List<BannerCreateDto> banners,
      List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraints,
      AccessibilityTimePeriodConstraintCreateDto accessibilityTimePeriodConstraint
   ) throws Exception {
      ConnectionCreateDto connectionCreateDto = null;
      switch (type) {
         case SSH:
            connectionCreateDto = new SshConnectionCreateDto();
            ((SshConnectionCreateDto)connectionCreateDto).setBastion(false);
            ((SshConnectionCreateDto)connectionCreateDto).setColorScheme(ColorScheme.BLACK_WHITE);
            ((SshConnectionCreateDto)connectionCreateDto).setFontSize(12);
            ((SshConnectionCreateDto)connectionCreateDto).setFileTransferMode(fileTransferMode);
            break;
         case RDP:
            connectionCreateDto = new RdpConnectionCreateDto();
            ((RdpConnectionCreateDto)connectionCreateDto).setFileTransferMode(fileTransferMode);
            ((RdpConnectionCreateDto)connectionCreateDto).setAttachConsole(false);
            ((RdpConnectionCreateDto)connectionCreateDto).setColorDepth(ColorDepth.CD_24);
            ((RdpConnectionCreateDto)connectionCreateDto).setDisableAudio(false);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableAnimation(true);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableAudioInput(false);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableConsoleAudio(false);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableFontSmoothing(true);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnablePrinting(false);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableTheme(true);
            ((RdpConnectionCreateDto)connectionCreateDto).setEnableWallpaper(true);
            ((RdpConnectionCreateDto)connectionCreateDto).setSecurityMode(RdpConnectionSecurityMode.ANY);
            ((RdpConnectionCreateDto)connectionCreateDto).setTrustServerCertificate(true);
            break;
         case VNC:
            connectionCreateDto = new VncConnectionCreateDto();
            ((VncConnectionCreateDto)connectionCreateDto).setClipboardEncoding(VncConnectionClipboardEncoding.UTF8);
            ((VncConnectionCreateDto)connectionCreateDto).setColorDepth(ColorDepth.CD_24);
            ((VncConnectionCreateDto)connectionCreateDto).setCursorMode(VncConnectionCursorMode.LOCAL);
            ((VncConnectionCreateDto)connectionCreateDto).setReadOnly(false);
            ((VncConnectionCreateDto)connectionCreateDto).setSwapRedBlue(false);
            break;
         case TELNET:
            connectionCreateDto = new TelnetConnectionCreateDto();
            ((TelnetConnectionCreateDto)connectionCreateDto).setBastion(false);
            ((TelnetConnectionCreateDto)connectionCreateDto).setColorScheme(ColorScheme.WHITE_BLACK);
            ((TelnetConnectionCreateDto)connectionCreateDto).setFontSize(12);
      }

      connectionCreateDto.setName(name);
      connectionCreateDto.setType(type);
      connectionCreateDto.setIpAddress(ipAddress);
      connectionCreateDto.setPort(port);
      connectionCreateDto.setClipboard(clipboardEnabled);
      connectionCreateDto.setCredentials(credential == null ? null : Stream.of(credential).collect(Collectors.toList()));
      connectionCreateDto.setBanners(banners);
      connectionCreateDto.setSessionInputConstraints(sessionInputConstraints);
      connectionCreateDto.setAccessibilityTimePeriodConstraint(accessibilityTimePeriodConstraint);
      super.create(connectionCreateDto);
   }

   @Override
   public String hasUserAlreadyAccessedToHost(long userId, String ipAddress, int port, ConnectionType type) {
      RepositoryContextManager.startNewTransaction();
      Connection connection = this.connectionRepository.findOneByIpAddressAndPortAndType(ipAddress, port, type);

      try {
         AccessRule accessRule = this.accessRuleService.getOneByUserAndConnection(userId, connection.getId());
         return accessRule.getName();
      } catch (Exception var8) {
         return null;
      }
   }

   @Override
   public Connection getOneByHostInfo(ConnectionType type, String ipAddress, int port, boolean readOnly) {
      JpaQuery<Connection> fetchConnectionByHostInfoQuery = new JpaQueryBuilder()
         .from(Connection.class, "c")
         .where(
            new FilterChainBuilder()
               .filter(
                  new FilterBuilder()
                     .string("ipAddress")
                     .eq(ipAddress)
                     .and()
                     .number("port")
                     .eq(port)
                     .and()
                     .number("type")
                     .eq(this.typeConverter.convertToDatabaseColumn(type))
                     .build()
               )
               .build()
         )
         .build();
      return Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchConnectionByHostInfoQuery, readOnly))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
   }

   @Override
   public Set<String> getAllConnectionsThatCurrentUserCanReviewTheirCaptures() {
      Long userId = this.authorizationService.getCurrentUserInfo().getId();
      return this.connectionRepository.allConnectionNamesAccessibleByUser(userId, Instant.now().getEpochSecond());
   }

   @Override
   public Connection getOneByTransparentPort(int port) {
      return Optional.ofNullable(this.connectionRepository.findOneByTransparentPort(port))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
   }

   @Override
   public ConnectionInfoDto convertToInfoDto(Connection connection) {
      if (connection == null) {
         return null;
      } else {
         ConnectionInfoDto connectionInfoDto = new ConnectionInfoDto();
         connectionInfoDto.setName(connection.getName());
         connectionInfoDto.setType(connection.getType());
         connectionInfoDto.setIpAddress(connection.getIpAddress());
         connectionInfoDto.setPort(connection.getPort());
         return connectionInfoDto;
      }
   }

   @Override
   public FileTransferMode resolveFileTransferMode(Connection connection) {
      if (connection == null) {
         return FileTransferMode.NONE;
      } else {
         switch (connection.getType()) {
            case SSH:
            case RDP:
               Class<?> targetClass = connection.getType().equals(ConnectionType.SSH) ? SshConnection.class : RdpConnection.class;
               return connection.getType().equals(ConnectionType.SSH)
                  ? ((SshConnection)this.readRepository
                        .findOne(new JpaQueryBuilder().from(targetClass, "c").where(QueryAndFilterUtils.idFilter(connection.getId())).build()))
                     .getFileTransferMode()
                  : ((RdpConnection)this.readRepository
                        .findOne(new JpaQueryBuilder().from(targetClass, "c").where(QueryAndFilterUtils.idFilter(connection.getId())).build()))
                     .getFileTransferMode();
            default:
               return FileTransferMode.NONE;
         }
      }
   }

   @Override
   public boolean resolveBastionStatus(Connection connection) {
      if (connection == null) {
         return false;
      } else {
         switch (connection.getType()) {
            case SSH:
            case TELNET:
               Class<?> targetClass = connection.getType().equals(ConnectionType.SSH) ? SshConnection.class : TelnetConnection.class;
               return connection.getType().equals(ConnectionType.SSH)
                  ? ((SshConnection)this.readRepository
                        .findOne(new JpaQueryBuilder().from(targetClass, "c").where(QueryAndFilterUtils.idFilter(connection.getId())).build()))
                     .isBastion()
                  : ((TelnetConnection)this.readRepository
                        .findOne(new JpaQueryBuilder().from(targetClass, "c").where(QueryAndFilterUtils.idFilter(connection.getId())).build()))
                     .isBastion();
            default:
               return true;
         }
      }
   }

   @Override
   public Set<Connection> getAllByAccessRuleId(long accessRuleId) {
      return this.connectionRepository.findAllByAccessRuleId(accessRuleId);
   }

   @Override
   public Credential getTypedCredential(Credential credential) {
      if (credential == null) {
         return null;
      } else {
         switch (credential.getType()) {
            case USERNAME_PASSWORD:
               return this.credentialRepository.findUsernamePasswordCredentialById(credential.getId());
            case DOMAIN:
               return this.credentialRepository.findDomainCredentialById(credential.getId());
            case PRIVATE_KEY:
               return this.credentialRepository.findPrivateKeyCredentialById(credential.getId());
            default:
               return null;
         }
      }
   }
}
