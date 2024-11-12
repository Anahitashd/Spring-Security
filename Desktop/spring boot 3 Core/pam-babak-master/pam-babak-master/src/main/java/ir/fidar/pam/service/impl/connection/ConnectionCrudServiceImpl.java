package ir.fidar.pam.service.impl.connection;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.license.register.LicenseInterceptingPoint;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.CredentialRepository;
import ir.fidar.pam.da.repository.RdpConnectionRemoteApplicationRepository;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.AccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodRepository;
import ir.fidar.pam.da.repository.connection.ConnectionRepository;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRulePrivilegesDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.dto.connection.ConnectionListDto;
import ir.fidar.pam.domain.dto.connection.ConnectionServicesDto;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationCreateDto;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationDetailsDto;
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.FileTransferSupportConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.RdpConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.SshConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.TelnetConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.create.VncConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.details.ConnectionDetailsDto;
import ir.fidar.pam.domain.dto.connection.details.RdpConnectionDetailsDto;
import ir.fidar.pam.domain.dto.connection.details.SshConnectionDetailsDto;
import ir.fidar.pam.domain.dto.connection.details.TelnetConnectionDetailsDto;
import ir.fidar.pam.domain.dto.connection.details.VncConnectionDetailsDto;
import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.dto.connection.update.RdpConnectionUpdateDto;
import ir.fidar.pam.domain.dto.connection.update.SshConnectionUpdateDto;
import ir.fidar.pam.domain.dto.connection.update.TelnetConnectionUpdateDto;
import ir.fidar.pam.domain.dto.connection.update.VncConnectionUpdateDto;
import ir.fidar.pam.domain.dto.credential.create.CredentialCreateDto;
import ir.fidar.pam.domain.dto.credential.create.DomainCredentialCreateDto;
import ir.fidar.pam.domain.dto.credential.create.PrivateKeyCredentialCreateDto;
import ir.fidar.pam.domain.dto.credential.create.UsernamePasswordCredentialCreateDto;
import ir.fidar.pam.domain.dto.credential.details.CredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.DomainCredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.PrivateKeyCredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.UsernamePasswordCredentialDetailsDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.connection.RdpConnection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.connection.SshConnection;
import ir.fidar.pam.domain.model.connection.TelnetConnection;
import ir.fidar.pam.domain.model.connection.VncConnection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.model.credential.DomainCredential;
import ir.fidar.pam.domain.model.credential.PrivateKeyCredential;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.CredentialType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.util.converter.attribbute.CredentialTypeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import ir.fidar.pam.exception.TimePeriodConstraintModeSpecificInfoNotProvidedException;
import ir.fidar.pam.exception.connection.ConnectionHasCapturedVideosException;
import ir.fidar.pam.exception.connection.ConnectionHostInfoAlreadyExists;
import ir.fidar.pam.exception.connection.ConnectionNameAlreadyExistsException;
import ir.fidar.pam.exception.connection.ConnectionTransparentPortAlreadyInUseException;
import ir.fidar.pam.exception.connection.RdpRemoteApplicationNameAlreadyExistsException;
import ir.fidar.pam.exception.connection.RemoteApplicationOnlySupportedByRdpConnectionException;
import ir.fidar.pam.exception.connection.UnsupportedCredentialTypeByConnectionException;
import ir.fidar.pam.exception.credential.CredentialLabelAlreadyExists;
import ir.fidar.pam.exception.credential.UnsupportedCredentialTypeException;
import ir.fidar.pam.exception.credential.UpdateCredentialTypeException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.CaptureRuleService;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.service.KavoshIntegrationService;
import ir.fidar.pam.service.connection.ConnectionCrudService;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.persistence.Tuple;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ConnectionCrudServiceImpl extends GlobalCommonServiceImpl<Connection> implements ConnectionCrudService {
   private final ConnectionRepository connectionRepository;
   private final GenericCrudRepository<SshConnection> sshConnectionCrudRepository;
   private final GenericCrudRepository<RdpConnection> rdpConnectionCrudRepository;
   private final GenericCrudRepository<VncConnection> vncConnectionCrudRepository;
   private final GenericCrudRepository<TelnetConnection> telnetConnectionCrudRepository;
   private final JpaQueryBasedReadRepository genericJpaQueryBasedReadRepository;
   private final NativeQueryBasedReadRepository genericNativeQueryBasedReadRepository;
   private final SessionInputConstraintRepository sessionInputConstraintRepository;
   private final AccessibilityTimePeriodConstraintRepository accessibilityTimePeriodConstraintRepository;
   private final GenericCrudRepository<AccessibilityTimePeriodConstraint> accessibilityTimePeriodConstraintCrudRepository;
   private final DailyAccessibilityTimePeriodConstraintRepository dailyAccessibilityTimePeriodConstraintRepository;
   private final GenericCrudRepository<DailyAccessibilityTimePeriodConstraint> dailyAccessibilityTimePeriodConstraintCrudRepository;
   private final WeeklyAccessibilityTimePeriodRepository weeklyAccessibilityTimePeriodRepository;
   private final GenericCrudRepository<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraintCrudRepository;
   private final MonthlyAccessibilityTimePeriodConstraintRepository monthlyAccessibilityTimePeriodConstraintRepository;
   private final GenericCrudRepository<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraintCrudRepository;
   private final GenericCrudRepository<SessionInputConstraintViolationHandler> sessionInputConstraintViolationHandlerCrudRepository;
   private final GenericCrudRepository<Banner> bannerCrudRepository;
   private final GenericCrudRepository<RdpConnectionRemoteApplication> rdpRemoteApplicationCrudRepository;
   private final RdpConnectionRemoteApplicationRepository rdpConnectionRemoteApplicationRepository;
   private final CredentialRepository credentialRepository;
   private final GenericCrudRepository<Credential> credentialCrudRepository;
   private final GenericCrudRepository<CaptureRule> captureRuleCrudRepository;
   protected final ConnectionTypeConverter typeConverter;
   private final CaptureService captureService;
   private final KavoshIntegrationService kavoshIntegrationService;
   private final CredentialTypeConverter credentialTypeConverter;
   private final AccessRuleService accessRuleService;
   private CaptureRuleService captureRuleService;

   public ConnectionCrudServiceImpl(
      ConnectionRepository connectionRepository,
      GenericCrudRepository<SshConnection> sshConnectionCrudRepository,
      GenericCrudRepository<RdpConnection> rdpConnectionCrudRepository,
      GenericCrudRepository<VncConnection> vncConnectionCrudRepository,
      GenericCrudRepository<TelnetConnection> telnetConnectionCrudRepository,
      JpaQueryBasedReadRepository genericJpaQueryBasedReadRepository,
      NativeQueryBasedReadRepository genericNativeQueryBasedReadRepository,
      SessionInputConstraintRepository sessionInputConstraintRepository,
      AccessibilityTimePeriodConstraintRepository accessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<AccessibilityTimePeriodConstraint> accessibilityTimePeriodConstraintCrudRepository,
      DailyAccessibilityTimePeriodConstraintRepository dailyAccessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<DailyAccessibilityTimePeriodConstraint> dailyAccessibilityTimePeriodConstraintCrudRepository,
      WeeklyAccessibilityTimePeriodRepository weeklyAccessibilityTimePeriodRepository,
      GenericCrudRepository<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraintCrudRepository,
      MonthlyAccessibilityTimePeriodConstraintRepository monthlyAccessibilityTimePeriodConstraintRepository,
      GenericCrudRepository<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraintCrudRepository,
      GenericCrudRepository<SessionInputConstraintViolationHandler> sessionInputConstraintViolationHandlerCrudRepository,
      GenericCrudRepository<Banner> bannerCrudRepository,
      RdpConnectionRemoteApplicationRepository rdpConnectionRemoteApplicationRepository,
      CredentialRepository credentialRepository,
      GenericCrudRepository<Credential> credentialCrudRepository,
      GenericCrudRepository<RdpConnectionRemoteApplication> rdpRemoteApplicationCrudRepository,
      GenericCrudRepository<CaptureRule> captureRuleCrudRepository,
      CaptureService captureService,
      KavoshIntegrationService kavoshIntegrationService,
      @Lazy AccessRuleService accessRuleService
   ) {
      super(connectionRepository);
      this.connectionRepository = connectionRepository;
      this.sshConnectionCrudRepository = sshConnectionCrudRepository;
      this.rdpConnectionCrudRepository = rdpConnectionCrudRepository;
      this.vncConnectionCrudRepository = vncConnectionCrudRepository;
      this.telnetConnectionCrudRepository = telnetConnectionCrudRepository;
      this.genericJpaQueryBasedReadRepository = genericJpaQueryBasedReadRepository;
      this.genericNativeQueryBasedReadRepository = genericNativeQueryBasedReadRepository;
      this.sessionInputConstraintRepository = sessionInputConstraintRepository;
      this.accessibilityTimePeriodConstraintRepository = accessibilityTimePeriodConstraintRepository;
      this.accessibilityTimePeriodConstraintCrudRepository = accessibilityTimePeriodConstraintCrudRepository;
      this.dailyAccessibilityTimePeriodConstraintRepository = dailyAccessibilityTimePeriodConstraintRepository;
      this.dailyAccessibilityTimePeriodConstraintCrudRepository = dailyAccessibilityTimePeriodConstraintCrudRepository;
      this.weeklyAccessibilityTimePeriodRepository = weeklyAccessibilityTimePeriodRepository;
      this.weeklyAccessibilityTimePeriodConstraintCrudRepository = weeklyAccessibilityTimePeriodConstraintCrudRepository;
      this.monthlyAccessibilityTimePeriodConstraintRepository = monthlyAccessibilityTimePeriodConstraintRepository;
      this.monthlyAccessibilityTimePeriodConstraintCrudRepository = monthlyAccessibilityTimePeriodConstraintCrudRepository;
      this.sessionInputConstraintViolationHandlerCrudRepository = sessionInputConstraintViolationHandlerCrudRepository;
      this.bannerCrudRepository = bannerCrudRepository;
      this.rdpConnectionRemoteApplicationRepository = rdpConnectionRemoteApplicationRepository;
      this.credentialRepository = credentialRepository;
      this.credentialCrudRepository = credentialCrudRepository;
      this.rdpRemoteApplicationCrudRepository = rdpRemoteApplicationCrudRepository;
      this.captureRuleCrudRepository = captureRuleCrudRepository;
      this.captureService = captureService;
      this.kavoshIntegrationService = kavoshIntegrationService;
      this.accessRuleService = accessRuleService;
      this.typeConverter = new ConnectionTypeConverter();
      this.credentialTypeConverter = new CredentialTypeConverter();
   }

   @Autowired
   public void setCaptureRuleService(CaptureRuleService captureRuleService) {
      this.captureRuleService = captureRuleService;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      NativeQuery connectionListQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("c", "c.id", "c.type", "c.name", "c.ipAddress", "c.port", "c.clipboard"))
         .from(Connection.class, "c")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> connectionListDtoList = this.nativeQueryBasedReadRepository.findAll(connectionListQuery, this::convertTupleToConnectionListDto);
      return Optional.of(connectionListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      NativePaginationQuery connectionListQuery = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(QueryAndFilterUtils.appendFullAuditionColumns("c", "c.id", "c.type", "c.name", "c.ipAddress", "c.port", "c.clipboard"))
         .from(Connection.class, "c")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> connectionListDtoPage = this.nativeQueryBasedReadRepository.find(connectionListQuery, this::convertTupleToConnectionListDto);
      return Optional.of(connectionListDtoPage);
   }

   public Optional<DetailsDto> load(String name) {
      JpaQuery jpaQuery = new JpaQueryBuilder()
         .from(Connection.class, "con")
         .leftJoin("connectionGroups", "cg")
         .fetch()
         .where(new FilterChainBuilder().filter(new FilterBuilder().string("name").eq(name).buildSingle()).build())
         .build();
      Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(jpaQuery))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      List<FilterChain> connectionFKFilter = this.connectionFkFilter(connection.getId());
      NativeQuery nativeQuery = new NativeQueryBuilder()
         .select("b.message", "b.skippable")
         .from(Banner.class, "b")
         .join(Connection.class, "con")
         .on("connection_id", "id")
         .where(connectionFKFilter)
         .build();
      List<BannerDetailsDto> banners = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         BannerDetailsDto bannerDetailsDto = new BannerDetailsDto();
         bannerDetailsDto.setMessage((String)tuple.get("message"));
         bannerDetailsDto.setSkippable((Boolean)tuple.get("skippable"));
         return bannerDetailsDto;
      });
      nativeQuery = new NativeQueryBuilder()
         .select("sh.*", "s.regex")
         .from(SessionInputConstraintViolationHandler.class, "sh")
         .join(SessionInputConstraint.class, "s")
         .on("constraint_id", "id")
         .where(connectionFKFilter)
         .build();
      List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         SessionInputConstraintViolationHandlerDetailsDto detailsDto = new SessionInputConstraintViolationHandlerDetailsDto();
         detailsDto.setConstraintRegex((String)tuple.get("regex"));
         detailsDto.setEmail((String)tuple.get("email"));
         detailsDto.setPhoneNumber((String)tuple.get("phone_number"));
         detailsDto.setTerminateSession((Boolean)tuple.get("terminate_session"));
         detailsDto.setAlertSomeone((Boolean)tuple.get("alert_someone"));
         detailsDto.setPreventExecution((Boolean)tuple.get("prevent_execution"));
         detailsDto.setSendNotification((Boolean)tuple.get("send_notification"));
         return detailsDto;
      });
      AccessibilityTimePeriodConstraint timePeriodConstraint = this.accessibilityTimePeriodConstraintRepository.findOneByConnectionId(connection.getId());
      AccessibilityTimePeriodConstraintDetailsDto timePeriodConstraintDetailsDto = null;
      if (timePeriodConstraint != null) {
         timePeriodConstraintDetailsDto = new AccessibilityTimePeriodConstraintDetailsDto();
         timePeriodConstraintDetailsDto.setMode(timePeriodConstraint.getMode());
         switch (timePeriodConstraint.getMode()) {
            case DAILY:
               DailyAccessibilityTimePeriodConstraint dailyAccessibilityTimePeriodConstraint = this.dailyAccessibilityTimePeriodConstraintRepository
                  .findOneByTimePeriodConstraintId(timePeriodConstraint.getId());
               DailyAccessibilityTimePeriodConstraintDto dailyAccessibilityTimePeriodConstraintDto = new DailyAccessibilityTimePeriodConstraintDto();
               dailyAccessibilityTimePeriodConstraintDto.setFromHour(dailyAccessibilityTimePeriodConstraint.getFromHour());
               dailyAccessibilityTimePeriodConstraintDto.setFromMinute(dailyAccessibilityTimePeriodConstraint.getFromMinute());
               dailyAccessibilityTimePeriodConstraintDto.setToHour(dailyAccessibilityTimePeriodConstraint.getToHour());
               dailyAccessibilityTimePeriodConstraintDto.setToMinute(dailyAccessibilityTimePeriodConstraint.getToMinute());
               timePeriodConstraintDetailsDto.setDailyConstraint(dailyAccessibilityTimePeriodConstraintDto);
               break;
            case WEEKLY:
               List<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraints = this.weeklyAccessibilityTimePeriodRepository
                  .findAllByTimePeriodConstraintId(timePeriodConstraint.getId());
               List<WeeklyAccessibilityTimePeriodConstraintDto> weeklyAccessibilityTimePeriodConstraintDtoList = new ArrayList<>();

               for (WeeklyAccessibilityTimePeriodConstraint weeklyAccessibilityTimePeriodConstraint : weeklyAccessibilityTimePeriodConstraints) {
                  WeeklyAccessibilityTimePeriodConstraintDto weeklyAccessibilityTimePeriodConstraintDto = new WeeklyAccessibilityTimePeriodConstraintDto();
                  weeklyAccessibilityTimePeriodConstraintDto.setWeekDay(weeklyAccessibilityTimePeriodConstraint.getWeekDay());
                  weeklyAccessibilityTimePeriodConstraintDto.setFromHour(weeklyAccessibilityTimePeriodConstraint.getFromHour());
                  weeklyAccessibilityTimePeriodConstraintDto.setFromMinute(weeklyAccessibilityTimePeriodConstraint.getFromMinute());
                  weeklyAccessibilityTimePeriodConstraintDto.setToHour(weeklyAccessibilityTimePeriodConstraint.getToHour());
                  weeklyAccessibilityTimePeriodConstraintDto.setToMinute(weeklyAccessibilityTimePeriodConstraint.getToMinute());
                  weeklyAccessibilityTimePeriodConstraintDtoList.add(weeklyAccessibilityTimePeriodConstraintDto);
               }

               timePeriodConstraintDetailsDto.setWeeklyConstraints(weeklyAccessibilityTimePeriodConstraintDtoList);
               break;
            case MONTHLY:
               List<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraints = this.monthlyAccessibilityTimePeriodConstraintRepository
                  .findAllByTimePeriodConstraintId(timePeriodConstraint.getId());
               List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyAccessibilityTimePeriodConstraintDtoList = new ArrayList<>();

               for (MonthlyAccessibilityTimePeriodConstraint monthlyAccessibilityTimePeriodConstraint : monthlyAccessibilityTimePeriodConstraints) {
                  MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto = new MonthlyAccessibilityTimePeriodConstraintDto();
                  monthlyAccessibilityTimePeriodConstraintDto.setMonthDay(monthlyAccessibilityTimePeriodConstraint.getMonthDay());
                  monthlyAccessibilityTimePeriodConstraintDto.setFromHour(monthlyAccessibilityTimePeriodConstraint.getFromHour());
                  monthlyAccessibilityTimePeriodConstraintDto.setFromMinute(monthlyAccessibilityTimePeriodConstraint.getFromMinute());
                  monthlyAccessibilityTimePeriodConstraintDto.setToHour(monthlyAccessibilityTimePeriodConstraint.getToHour());
                  monthlyAccessibilityTimePeriodConstraintDto.setToMinute(monthlyAccessibilityTimePeriodConstraint.getToMinute());
                  monthlyAccessibilityTimePeriodConstraintDtoList.add(monthlyAccessibilityTimePeriodConstraintDto);
               }

               timePeriodConstraintDetailsDto.setMonthlyConstraints(monthlyAccessibilityTimePeriodConstraintDtoList);
         }
      }

      List<Credential> credentials = this.credentialRepository.findAllByConnectionId(connection.getId());
      List<CredentialDetailsDto> credentialDetailsDtoList = new ArrayList<>();

      for (Credential credential : credentials) {
         switch (credential.getType()) {
            case USERNAME_PASSWORD:
               UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential)credential;
               UsernamePasswordCredentialDetailsDto usernamePasswordCredentialDetailsDto = new UsernamePasswordCredentialDetailsDto();
               usernamePasswordCredentialDetailsDto.setType(usernamePasswordCredential.getType());
               usernamePasswordCredentialDetailsDto.setLabel(usernamePasswordCredential.getLabel());
               usernamePasswordCredentialDetailsDto.setUsername(usernamePasswordCredential.getUsername());
               credentialDetailsDtoList.add(usernamePasswordCredentialDetailsDto);
               break;
            case DOMAIN:
               DomainCredential domainCredential = (DomainCredential)credential;
               DomainCredentialDetailsDto domainCredentialDetailsDto = new DomainCredentialDetailsDto();
               domainCredentialDetailsDto.setType(domainCredential.getType());
               domainCredentialDetailsDto.setLabel(domainCredential.getLabel());
               domainCredentialDetailsDto.setUsername(domainCredential.getUsername());
               domainCredentialDetailsDto.setDomain(domainCredential.getDomain());
               credentialDetailsDtoList.add(domainCredentialDetailsDto);
               break;
            case PRIVATE_KEY:
               PrivateKeyCredential privateKeyCredential = (PrivateKeyCredential)credential;
               PrivateKeyCredentialDetailsDto privateKeyCredentialDetailsDto = new PrivateKeyCredentialDetailsDto();
               privateKeyCredentialDetailsDto.setType(privateKeyCredential.getType());
               privateKeyCredentialDetailsDto.setLabel(privateKeyCredential.getLabel());
               privateKeyCredentialDetailsDto.setUsername(privateKeyCredential.getUsername());
               credentialDetailsDtoList.add(privateKeyCredentialDetailsDto);
         }
      }

      ConnectionDetailsDto connectionDetailsDto = null;
      switch (connection.getType()) {
         case RDP:
            connectionDetailsDto = new RdpConnectionDetailsDto();
            break;
         case SSH:
            connectionDetailsDto = new SshConnectionDetailsDto();
            break;
         case VNC:
            connectionDetailsDto = new VncConnectionDetailsDto();
            break;
         case TELNET:
            connectionDetailsDto = new TelnetConnectionDetailsDto();
            break;
         default:
            throw new IllegalStateException(String.format("Unknown connection type: $s", connection.getType().toString()));
      }

      connectionDetailsDto.setType(connection.getType());
      connectionDetailsDto.setName(connection.getName());
      connectionDetailsDto.setIpAddress(connection.getIpAddress());
      connectionDetailsDto.setPort(connection.getPort());
      connectionDetailsDto.setClipboard(connection.isClipboard());
      connectionDetailsDto.setMaximumConcurrentSessions(connection.getMaximumConcurrentSessions());
      connectionDetailsDto.setMaximumConcurrentSessionsPerUser(connection.getMaximumConcurrentSessionsPerUser());
      connectionDetailsDto.setTransparentPort(connection.getTransparentPort());
      connectionDetailsDto.setBanners(banners);
      connectionDetailsDto.setSessionInputConstraints(sessionInputConstraints);
      connectionDetailsDto.setAccessibilityTimePeriodConstraint(timePeriodConstraintDetailsDto);
      connectionDetailsDto.setCredentials(credentialDetailsDtoList);
      List<ConnectionGroupInfoDto> connectionGroupInfoDtoList = new ArrayList<>();

      for (ConnectionGroup connectionGroup : connection.getConnectionGroups()) {
         ConnectionGroupInfoDto connectionGroupInfoDto = new ConnectionGroupInfoDto();
         connectionGroupInfoDto.setName(connectionGroup.getName());
         connectionGroupInfoDtoList.add(connectionGroupInfoDto);
      }

      connectionDetailsDto.setConnectionGroups(connectionGroupInfoDtoList);
      connectionDetailsDto = this.copyConnectionTypeSpecificParametersToDetailsDto(connection, connectionDetailsDto);
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)connection, (AbstractDescriptiveDto)connectionDetailsDto);
      return Optional.of(connectionDetailsDto);
   }

   @LicenseInterceptingPoint
   public void create(ConnectionCreateDto connectionCreateDto) throws Exception {
      if (this.existsByName(connectionCreateDto.getName())) {
         throw new ResourceAlreadyExistsException(new ConnectionNameAlreadyExistsException());
      } else if (this.existsByHostInfo(connectionCreateDto.getType(), connectionCreateDto.getIpAddress(), connectionCreateDto.getPort())) {
         throw new ResourceAlreadyExistsException(new ConnectionHostInfoAlreadyExists());
      } else {
         this.checkAVScannerServerReachability(connectionCreateDto);
         RepositoryContextManager.startNewTransaction();

         try {
            Connection connection = new Connection();
            connection.setType(connectionCreateDto.getType());
            connection.setName(connectionCreateDto.getName());
            connection.setIpAddress(connectionCreateDto.getIpAddress());
            connection.setPort(connectionCreateDto.getPort());
            connection.setClipboard(connectionCreateDto.isClipboard());
            connection.setMaximumConcurrentSessions(connectionCreateDto.getMaximumConcurrentSessions());
            connection.setMaximumConcurrentSessionsPerUser(connectionCreateDto.getMaximumConcurrentSessionsPerUser());
            connection.setDescription(connectionCreateDto.getDescription());
            if (connectionCreateDto.getAccessibilityTimePeriodConstraint() != null) {
               this.setAccessibilityTimePeriodConstraintForConnection(connectionCreateDto.getAccessibilityTimePeriodConstraint(), connection);
            }

            if (connectionCreateDto.getSessionInputConstraints() != null && !connectionCreateDto.getSessionInputConstraints().isEmpty()) {
               this.setSessionInputConstraintsToConnection(connectionCreateDto.getSessionInputConstraints(), connection);
            }

            if (connectionCreateDto.getBanners() != null && !connectionCreateDto.getBanners().isEmpty()) {
               this.setBannersToConnection(connectionCreateDto.getBanners(), connection);
            }

            if (connectionCreateDto.getCredentials() != null && !connectionCreateDto.getCredentials().isEmpty()) {
               Set<String> credentialLabels = new HashSet<>();

               for (CredentialCreateDto credentialCreateDto : connectionCreateDto.getCredentials()) {
                  if (credentialLabels.contains(credentialCreateDto.getLabel())) {
                     throw new CredentialLabelAlreadyExists(credentialCreateDto.getLabel());
                  }

                  this.validateCredentialSupportByConnection(credentialCreateDto.getType(), connection.getType());
                  connection.addCredential(this.convertCredentialCreateDtoToCredential(credentialCreateDto, connection));
                  credentialLabels.add(credentialCreateDto.getLabel());
               }
            }

            if (connectionCreateDto.getTransparentPort() != null && this.connectionRepository.existsByTransparentPort(connectionCreateDto.getTransparentPort())
               )
             {
               throw new ConnectionTransparentPortAlreadyInUseException();
            } else {
               connection.setTransparentPort(connectionCreateDto.getTransparentPort());
               switch (connectionCreateDto.getType()) {
                  case RDP:
                     RdpConnection rdpConnection = new RdpConnection();
                     RdpConnectionCreateDto rdpConnectionCreateDto = (RdpConnectionCreateDto)connectionCreateDto;
                     rdpConnection.setConnection(connection);
                     this.copyRdpSpecificParametersToConnection(rdpConnection, rdpConnectionCreateDto);
                     this.rdpConnectionCrudRepository.save(rdpConnection);
                     break;
                  case SSH:
                     SshConnection sshConnection = new SshConnection();
                     SshConnectionCreateDto sshConnectionCreateDto = (SshConnectionCreateDto)connectionCreateDto;
                     sshConnection.setConnection(connection);
                     this.copySshSpecificParametersToConnection(sshConnection, sshConnectionCreateDto);
                     this.sshConnectionCrudRepository.save(sshConnection);
                     break;
                  case VNC:
                     VncConnection vncConnection = new VncConnection();
                     VncConnectionCreateDto vncConnectionCreateDto = (VncConnectionCreateDto)connectionCreateDto;
                     vncConnection.setConnection(connection);
                     this.copyVncSpecificParametersToConnection(vncConnection, vncConnectionCreateDto);
                     this.vncConnectionCrudRepository.save(vncConnection);
                     break;
                  case TELNET:
                     TelnetConnection telnetConnection = new TelnetConnection();
                     TelnetConnectionCreateDto telnetConnectionCreateDto = (TelnetConnectionCreateDto)connectionCreateDto;
                     telnetConnection.setConnection(connection);
                     this.copyTelnetSpecificParametersToConnection(telnetConnection, telnetConnectionCreateDto);
                     this.telnetConnectionCrudRepository.save(telnetConnection);
               }

               this.crudRepository.save(connection);
               RepositoryContextManager.commit();
            }
         } catch (Exception var6) {
            RepositoryContextManager.rollback();
            throw var6;
         }
      }
   }

   public void update(String name, ConnectionUpdateDto connectionUpdateDto) throws Exception {
      JpaQuery<Connection> connectionJpaFetchQuery = new JpaQueryBuilder()
         .from(Connection.class, "con")
         .leftJoin("accessibilityTimePeriodConstraint", "atpc")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(connectionJpaFetchQuery, false))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      if (!connectionUpdateDto.getName().equalsIgnoreCase(connection.getName()) && this.existsByName(connectionUpdateDto.getName())) {
         throw new ResourceAlreadyExistsException(new ConnectionNameAlreadyExistsException());
      } else if ((
            !connection.getType().equals(connectionUpdateDto.getType())
               || !connection.getIpAddress().equalsIgnoreCase(connectionUpdateDto.getIpAddress())
               || connection.getPort() != connectionUpdateDto.getPort()
         )
         && this.existsByHostInfo(connectionUpdateDto.getType(), connectionUpdateDto.getIpAddress(), connectionUpdateDto.getPort())) {
         throw new ResourceAlreadyExistsException(new ConnectionHostInfoAlreadyExists());
      } else {
         this.checkAVScannerServerReachability(connectionUpdateDto);
         List<FilterChain> connectionFkFilter = this.connectionFkFilter(connection.getId());
         RepositoryContextManager.startNewTransaction();

         try {
            AccessibilityTimePeriodConstraint timePeriodConstraint = connection.getAccessibilityTimePeriodConstraint();
            if (connectionUpdateDto.getAccessibilityTimePeriodConstraint() == null) {
               if (timePeriodConstraint != null) {
                  connection.setAccessibilityTimePeriodConstraint(null);
                  RepositoryContextManager.getUnderlyingEntityManager().remove(timePeriodConstraint);
               }
            } else if (timePeriodConstraint == null) {
               this.setAccessibilityTimePeriodConstraintForConnection(connectionUpdateDto.getAccessibilityTimePeriodConstraint(), connection);
            } else {
               AccessibilityTimePeriodConstraintCreateDto timePeriodConstraintCreateDto = connectionUpdateDto.getAccessibilityTimePeriodConstraint();
               List<FilterChain> timePeriodConstraintIdFilter = new FilterChainBuilder()
                  .filter(new FilterBuilder().number("time_period_id").eq(timePeriodConstraint.getId()).buildSingle())
                  .build();
               boolean sameMode = timePeriodConstraintCreateDto.getMode().equals(timePeriodConstraint.getMode());
               timePeriodConstraint.setMode(timePeriodConstraintCreateDto.getMode());
               timePeriodConstraint.setTimezone(this.authorizationService.getCurrentUserInfo().getTimezone());
               switch (timePeriodConstraintCreateDto.getMode()) {
                  case DAILY:
                     DailyAccessibilityTimePeriodConstraint dailyAccessibilityTimePeriodConstraint;
                     if (!sameMode) {
                        timePeriodConstraint.setWeeklyConstraints(null);
                        timePeriodConstraint.setMonthlyConstraints(null);
                        if (timePeriodConstraint.getMode().equals(AccessibilityTimePeriodMode.WEEKLY)) {
                           this.weeklyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(WeeklyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        } else {
                           this.monthlyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(MonthlyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        }

                        dailyAccessibilityTimePeriodConstraint = new DailyAccessibilityTimePeriodConstraint();
                     } else {
                        dailyAccessibilityTimePeriodConstraint = (DailyAccessibilityTimePeriodConstraint)this.genericJpaQueryBasedReadRepository
                           .findOne(
                              new JpaQueryBuilder()
                                 .from(DailyAccessibilityTimePeriodConstraint.class, "datpc")
                                 .where(QueryAndFilterUtils.foreignKeyFilter("timePeriodConstraint.id", timePeriodConstraint.getId()))
                                 .build(),
                              false
                           );
                     }

                     dailyAccessibilityTimePeriodConstraint.setTimePeriodConstraint(timePeriodConstraint);
                     dailyAccessibilityTimePeriodConstraint.setFromHour(timePeriodConstraintCreateDto.getDailyConstraint().getFromHour());
                     dailyAccessibilityTimePeriodConstraint.setFromMinute(timePeriodConstraintCreateDto.getDailyConstraint().getFromMinute());
                     dailyAccessibilityTimePeriodConstraint.setToHour(timePeriodConstraintCreateDto.getDailyConstraint().getToHour());
                     dailyAccessibilityTimePeriodConstraint.setToMinute(timePeriodConstraintCreateDto.getDailyConstraint().getToMinute());
                     timePeriodConstraint.setDailyConstraint(dailyAccessibilityTimePeriodConstraint);
                     break;
                  case WEEKLY:
                     if (!sameMode) {
                        timePeriodConstraint.setDailyConstraint(null);
                        timePeriodConstraint.setMonthlyConstraints(null);
                        if (timePeriodConstraint.getMode().equals(AccessibilityTimePeriodMode.DAILY)) {
                           this.dailyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(DailyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        } else {
                           this.monthlyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(MonthlyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        }
                     } else {
                        this.weeklyAccessibilityTimePeriodConstraintCrudRepository
                           .remove(WeeklyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                     }

                     this.setWeeklyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
                        timePeriodConstraintCreateDto.getWeeklyConstraints(), timePeriodConstraint
                     );
                     break;
                  case MONTHLY:
                     if (!sameMode) {
                        timePeriodConstraint.setDailyConstraint(null);
                        timePeriodConstraint.setWeeklyConstraints(null);
                        if (timePeriodConstraint.getMode().equals(AccessibilityTimePeriodMode.DAILY)) {
                           this.dailyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(DailyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        } else {
                           this.weeklyAccessibilityTimePeriodConstraintCrudRepository
                              .remove(WeeklyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                        }
                     } else {
                        this.monthlyAccessibilityTimePeriodConstraintCrudRepository
                           .remove(MonthlyAccessibilityTimePeriodConstraint.class, timePeriodConstraintIdFilter);
                     }

                     this.setMonthlyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
                        timePeriodConstraintCreateDto.getMonthlyConstraints(), timePeriodConstraint
                     );
               }

               this.accessibilityTimePeriodConstraintCrudRepository.update(timePeriodConstraint);
            }

            this.sessionInputConstraintViolationHandlerCrudRepository.remove(SessionInputConstraintViolationHandler.class, connectionFkFilter);
            if (connectionUpdateDto.getSessionInputConstraints() != null && !connectionUpdateDto.getSessionInputConstraints().isEmpty()) {
               this.setSessionInputConstraintsToConnection(connectionUpdateDto.getSessionInputConstraints(), connection);
            }

            this.bannerCrudRepository.remove(Banner.class, connectionFkFilter);
            if (connectionUpdateDto.getBanners() != null && !connectionUpdateDto.getBanners().isEmpty()) {
               this.setBannersToConnection(connectionUpdateDto.getBanners(), connection);
            }

            List<Credential> credentials = this.genericJpaQueryBasedReadRepository
               .findAll(
                  new JpaQueryBuilder()
                     .from(Credential.class, "c")
                     .where(new FilterChainBuilder().filter(new FilterBuilder().number("connection.id").eq(connection.getId()).buildSingle()).build())
                     .build(),
                  false
               );
            if (connectionUpdateDto.getCredentials() != null && !connectionUpdateDto.getCredentials().isEmpty()) {
               List<Credential> oldCredentials = new ArrayList<>(credentials);
               Set<Credential> newCredentials = new HashSet<>();
               Set<String> newCredentialLabels = new HashSet<>();

               for (CredentialCreateDto credentialCreateDto : connectionUpdateDto.getCredentials()) {
                  Credential newCredential = this.convertCredentialCreateDtoToCredential(credentialCreateDto, connection);
                  newCredentials.add(newCredential);
                  if (newCredentialLabels.contains(newCredential.getLabel())) {
                     throw new CredentialLabelAlreadyExists(credentialCreateDto.getLabel());
                  }

                  newCredentialLabels.add(newCredential.getLabel());
                  int index = oldCredentials.indexOf(newCredential);
                  if (index != -1) {
                     Credential oldCredential = oldCredentials.get(index);
                     if (!oldCredential.getType().equals(newCredential.getType())) {
                        throw new UpdateCredentialTypeException();
                     }

                     switch (oldCredential.getType()) {
                        case USERNAME_PASSWORD:
                           UsernamePasswordCredential oldUsernamePasswordCredential = (UsernamePasswordCredential)oldCredential;
                           UsernamePasswordCredential newUsernamePasswordCredential = (UsernamePasswordCredential)newCredential;
                           oldUsernamePasswordCredential.setUsername(newUsernamePasswordCredential.getUsername());
                           if (StringUtils.hasContent(newUsernamePasswordCredential.getPassword())) {
                              oldUsernamePasswordCredential.setPassword(newUsernamePasswordCredential.getPassword());
                           }

                           this.credentialCrudRepository.update(oldUsernamePasswordCredential);
                           break;
                        case DOMAIN:
                           DomainCredential oldDomainCredential = (DomainCredential)oldCredential;
                           DomainCredential newDomainCredential = (DomainCredential)newCredential;
                           oldDomainCredential.setUsername(newDomainCredential.getUsername());
                           if (StringUtils.hasContent(newDomainCredential.getPassword())) {
                              oldDomainCredential.setPassword(newDomainCredential.getPassword());
                           }

                           oldDomainCredential.setDomain(newDomainCredential.getDomain());
                           this.credentialCrudRepository.update(oldDomainCredential);
                           break;
                        case PRIVATE_KEY:
                           PrivateKeyCredential oldPrivateKeyCredential = (PrivateKeyCredential)oldCredential;
                           PrivateKeyCredential newPrivateKeyCredential = (PrivateKeyCredential)newCredential;
                           oldPrivateKeyCredential.setUsername(newPrivateKeyCredential.getUsername());
                           if (StringUtils.hasContent(newPrivateKeyCredential.getPrivateKey())) {
                              oldPrivateKeyCredential.setPrivateKey(newPrivateKeyCredential.getPrivateKey());
                           }

                           if (StringUtils.hasContent(newPrivateKeyCredential.getPassphrase())) {
                              oldPrivateKeyCredential.setPassphrase(newPrivateKeyCredential.getPassphrase());
                           }

                           this.credentialCrudRepository.update(oldPrivateKeyCredential);
                     }
                  }
               }

               Set<Credential> temp = new HashSet<>(oldCredentials);
               temp.removeAll(newCredentials);

               for (Credential credential : temp) {
                  connection.removeCredential(credential);
                  RepositoryContextManager.getUnderlyingEntityManager().remove(credential);
               }

               temp.clear();
               temp.addAll(newCredentials);
               temp.removeAll(oldCredentials);

               for (Credential credential : temp) {
                  connection.addCredential(credential);
               }
            } else {
               for (Credential credential : credentials) {
                  RepositoryContextManager.getUnderlyingEntityManager().remove(credential);
                  RepositoryContextManager.getUnderlyingEntityManager().flush();
               }
            }

            connection.setName(connectionUpdateDto.getName());
            connection.setIpAddress(connectionUpdateDto.getIpAddress());
            connection.setPort(connectionUpdateDto.getPort());
            connection.setDescription(connectionUpdateDto.getDescription());
            connection.setMaximumConcurrentSessions(connectionUpdateDto.getMaximumConcurrentSessions());
            connection.setMaximumConcurrentSessionsPerUser(connectionUpdateDto.getMaximumConcurrentSessionsPerUser());
            connection.setClipboard(connectionUpdateDto.isClipboard());
            if (connectionUpdateDto.getTransparentPort() == null) {
               if (connection.getTransparentPort() != null) {
               }
            } else if (!connectionUpdateDto.getTransparentPort().equals(connection.getTransparentPort())
               && this.connectionRepository.existsByTransparentPort(connectionUpdateDto.getTransparentPort())) {
               throw new ConnectionTransparentPortAlreadyInUseException();
            }

            connection.setTransparentPort(connectionUpdateDto.getTransparentPort());
            if (connection.getType().equals(connectionUpdateDto.getType())) {
               switch (connectionUpdateDto.getType()) {
                  case RDP:
                     RdpConnection rdpConnection = this.rdpConnectionCrudRepository.findOne(RdpConnection.class, connection.getId());
                     RdpConnectionUpdateDto rdpConnectionUpdateDto = (RdpConnectionUpdateDto)connectionUpdateDto;
                     rdpConnection.setFileTransferMode(rdpConnectionUpdateDto.getFileTransferMode());
                     this.copyRdpSpecificParametersToConnection(rdpConnection, rdpConnectionUpdateDto);
                     this.rdpConnectionCrudRepository.update(rdpConnection);
                     break;
                  case SSH:
                     SshConnection sshConnection = this.sshConnectionCrudRepository.findOne(SshConnection.class, connection.getId());
                     SshConnectionUpdateDto sshConnectionUpdateDto = (SshConnectionUpdateDto)connectionUpdateDto;
                     sshConnection.setFileTransferMode(sshConnectionUpdateDto.getFileTransferMode());
                     sshConnection.setBastion(sshConnectionUpdateDto.isBastion());
                     this.copySshSpecificParametersToConnection(sshConnection, sshConnectionUpdateDto);
                     this.sshConnectionCrudRepository.update(sshConnection);
                     break;
                  case VNC:
                     VncConnection vncConnection = this.vncConnectionCrudRepository.findOne(VncConnection.class, connection.getId());
                     VncConnectionUpdateDto vncConnectionUpdateDto = (VncConnectionUpdateDto)connectionUpdateDto;
                     this.copyVncSpecificParametersToConnection(vncConnection, vncConnectionUpdateDto);
                     this.vncConnectionCrudRepository.update(vncConnection);
                     break;
                  case TELNET:
                     TelnetConnection telnetConnection = this.telnetConnectionCrudRepository.findOne(TelnetConnection.class, connection.getId());
                     TelnetConnectionUpdateDto telnetConnectionUpdateDto = (TelnetConnectionUpdateDto)connectionUpdateDto;
                     this.copyTelnetSpecificParametersToConnection(telnetConnection, telnetConnectionUpdateDto);
                     this.telnetConnectionCrudRepository.update(telnetConnection);
               }
            } else {
               this.deleteConnectionSpecificType(connection);
               connection.setType(connectionUpdateDto.getType());
               switch (connectionUpdateDto.getType()) {
                  case RDP:
                     RdpConnection rdpConnection = new RdpConnection();
                     rdpConnection.setConnection(connection);
                     RdpConnectionUpdateDto rdpConnectionUpdateDto = (RdpConnectionUpdateDto)connectionUpdateDto;
                     this.copyRdpSpecificParametersToConnection(rdpConnection, rdpConnectionUpdateDto);
                     this.rdpConnectionCrudRepository.save(rdpConnection);
                     break;
                  case SSH:
                     SshConnection sshConnection = new SshConnection();
                     sshConnection.setConnection(connection);
                     SshConnectionUpdateDto sshConnectionUpdateDto = (SshConnectionUpdateDto)connectionUpdateDto;
                     this.copySshSpecificParametersToConnection(sshConnection, sshConnectionUpdateDto);
                     this.sshConnectionCrudRepository.save(sshConnection);
                     break;
                  case VNC:
                     VncConnection vncConnection = new VncConnection();
                     vncConnection.setConnection(connection);
                     VncConnectionUpdateDto vncConnectionUpdateDto = (VncConnectionUpdateDto)connectionUpdateDto;
                     this.copyVncSpecificParametersToConnection(vncConnection, vncConnectionUpdateDto);
                     this.vncConnectionCrudRepository.save(vncConnection);
                     break;
                  case TELNET:
                     TelnetConnection telnetConnection = new TelnetConnection();
                     telnetConnection.setConnection(connection);
                     TelnetConnectionUpdateDto telnetConnectionUpdateDto = (TelnetConnectionUpdateDto)connectionUpdateDto;
                     this.copyTelnetSpecificParametersToConnection(telnetConnection, telnetConnectionUpdateDto);
                     this.telnetConnectionCrudRepository.save(telnetConnection);
               }

               this.crudRepository.update(connection);
               RepositoryContextManager.commit();
            }
         } catch (Exception var18) {
            RepositoryContextManager.rollback();
            throw var18;
         }
      }
   }

   public void delete(String name) throws Exception {
      RepositoryContextManager.startNewTransaction();

      try {
         Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionWithAllGropsByNameQuery(name), false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
         if (this.captureService.existAnyCapturedVideoForConnection(connection.getName())) {
            throw new ConnectionHasCapturedVideosException();
         } else {
            this.deleteConnectionSpecificType(connection);

            for (ConnectionGroup connectionGroup : connection.getConnectionGroups()) {
               connectionGroup.removeConnection(connection);
            }

            this.checkCaptureRulesAndRemoveIfRequired(connection);
            this.crudRepository.remove(connection);
            RepositoryContextManager.commit();
         }
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }
   }

   @Override
   public Optional<List<CredentialDetailsDto>> loadCredentialsOfSpecificConnection(String connectionName) {
      Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionByNameQuery(connectionName)))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      NativeQuery fetchCredentialLabelsOfConnectionQuery = new NativeQueryBuilder()
         .select("c.label", "c.type")
         .from(Credential.class, "c")
         .where(this.connectionFkFilter(connection.getId()))
         .build();
      List<CredentialDetailsDto> credentialDetailsDtoList = this.nativeQueryBasedReadRepository
         .findAll(
            fetchCredentialLabelsOfConnectionQuery,
            tuple -> {
               CredentialDetailsDto credentialDetailsDto = new CredentialDetailsDto();
               credentialDetailsDto.setLabel((String)tuple.get("label"));
               credentialDetailsDto.setType(
                  this.credentialTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue()))
               );
               return credentialDetailsDto;
            }
         );
      return Optional.of(credentialDetailsDtoList);
   }

   @Override
   public Optional<ConnectionServicesDto> loadServicesOfSpecificConnection(String connectionName) {
      Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionByNameQuery(connectionName)))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      NativeQuery query = new NativeQueryBuilder()
         .select("b.message", "b.skippable")
         .from(Banner.class, "b")
         .where(this.connectionFkFilter(connection.getId()))
         .build();
      List<BannerDetailsDto> banners = this.nativeQueryBasedReadRepository.findAll(query, tuple -> {
         BannerDetailsDto bannerDetailsDto = new BannerDetailsDto();
         bannerDetailsDto.setMessage(tuple.get(0).toString());
         bannerDetailsDto.setSkippable(Boolean.parseBoolean(tuple.get(1).toString()));
         return bannerDetailsDto;
      });
      query = new NativeQueryBuilder()
         .select("sich.*", "sic.regex")
         .from(SessionInputConstraintViolationHandler.class, "sich")
         .join(SessionInputConstraint.class, "sic")
         .on("constraint_id", "id")
         .where(this.connectionFkFilter(connection.getId()))
         .build();
      List<SessionInputConstraintViolationHandlerDetailsDto> sessionInputConstraints = this.nativeQueryBasedReadRepository
         .findAll(
            query,
            tuple -> {
               SessionInputConstraintViolationHandlerDetailsDto sessionInputConstraintViolationHandlerDetailsDto = new SessionInputConstraintViolationHandlerDetailsDto(
                  
               );
               sessionInputConstraintViolationHandlerDetailsDto.setConstraintRegex(tuple.get("regex").toString());
               sessionInputConstraintViolationHandlerDetailsDto.setAlertSomeone(Boolean.parseBoolean(tuple.get("alert_someone").toString()));
               sessionInputConstraintViolationHandlerDetailsDto.setPreventExecution(Boolean.parseBoolean(tuple.get("prevent_execution").toString()));
               sessionInputConstraintViolationHandlerDetailsDto.setTerminateSession(Boolean.parseBoolean(tuple.get("terminate_session").toString()));
               sessionInputConstraintViolationHandlerDetailsDto.setSendNotification(Boolean.parseBoolean(tuple.get("send_notification").toString()));
               sessionInputConstraintViolationHandlerDetailsDto.setEmail((String)tuple.get("email"));
               sessionInputConstraintViolationHandlerDetailsDto.setPhoneNumber((String)tuple.get("phone_number"));
               return sessionInputConstraintViolationHandlerDetailsDto;
            }
         );
      ConnectionServicesDto connectionServicesDto = new ConnectionServicesDto();
      connectionServicesDto.setBanners(banners);
      connectionServicesDto.setSessionInputConstraints(sessionInputConstraints);
      return Optional.of(connectionServicesDto);
   }

   @Override
   public Optional<CaptureRulePrivilegesDto> loadCapturePrivilegesOfCurrentUserOnSpecificConnection(String connectionName) throws InsufficientPrivilegeToAccessCaptureException {
      Connection connection = Optional.ofNullable(this.connectionRepository.findOneByNameIgnoreCase(connectionName))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      CaptureRule captureRule = this.captureRuleService
         .getCaptureRuleOfUserOverConnection(super.authorizationService.getCurrentUserInfo().getId(), connection.getId());
      if (captureRule == null) {
         throw new InsufficientPrivilegeToAccessCaptureException();
      } else {
         CaptureRulePrivilegesDto captureRulePrivilegesDto = new CaptureRulePrivilegesDto();
         captureRulePrivilegesDto.setExport(captureRule.isExport());
         captureRulePrivilegesDto.setKeystroke(captureRule.isKeystroke());
         return Optional.of(captureRulePrivilegesDto);
      }
   }

   @Override
   public Optional<List<RdpConnectionRemoteApplicationDetailsDto>> loadRemoteApplicationsOfSpecificConnection(String connectionName) throws RemoteApplicationOnlySupportedByRdpConnectionException {
      Connection connection = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionByNameQuery(connectionName)))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Connection.class)));
      if (!connection.getType().equals(ConnectionType.RDP)) {
         throw new RemoteApplicationOnlySupportedByRdpConnectionException();
      } else {
         List<RdpConnectionRemoteApplication> rdpConnectionRemoteApplications = this.rdpConnectionRemoteApplicationRepository
            .findAllByConnectionId(connection.getId());
         List<RdpConnectionRemoteApplicationDetailsDto> remoteApplicationDetailsDtoList = rdpConnectionRemoteApplications.stream()
            .map(this::convertRdpRemoteApplicationToRdpRemoteApplicationDetailsDto)
            .collect(Collectors.toList());
         return Optional.of(remoteApplicationDetailsDtoList);
      }
   }

   private ConnectionDetailsDto copyConnectionTypeSpecificParametersToDetailsDto(Connection connection, ConnectionDetailsDto connectionDetailsDto) {
      switch (connection.getType()) {
         case RDP:
            RdpConnection rdpConnection = this.rdpConnectionCrudRepository.findOne(RdpConnection.class, connection.getId());
            RdpConnectionDetailsDto rdpConnectionDetailsDto = (RdpConnectionDetailsDto)connectionDetailsDto;
            rdpConnectionDetailsDto.setAttachConsole(rdpConnection.isAttachConsole());
            rdpConnectionDetailsDto.setColorDepth(rdpConnection.getColorDepth());
            rdpConnectionDetailsDto.setDisableAudio(rdpConnection.isDisableAudio());
            rdpConnectionDetailsDto.setEnableAnimation(rdpConnection.isEnableAnimation());
            rdpConnectionDetailsDto.setEnableConsoleAudio(rdpConnection.isEnableConsoleAudio());
            rdpConnectionDetailsDto.setEnableFontSmoothing(rdpConnection.isEnableFontSmoothing());
            rdpConnectionDetailsDto.setEnablePrinting(rdpConnection.isEnablePrinting());
            rdpConnectionDetailsDto.setEnableAudioInput(rdpConnection.isEnableAudioInput());
            rdpConnectionDetailsDto.setEnableTheme(rdpConnection.isEnableTheme());
            rdpConnectionDetailsDto.setEnableWallpaper(rdpConnection.isEnableWallpaper());
            rdpConnectionDetailsDto.setSecurityMode(rdpConnection.getSecurityMode());
            rdpConnectionDetailsDto.setStartupAppName(rdpConnection.getStartupAppName());
            rdpConnectionDetailsDto.setTrustServerCertificate(rdpConnection.isTrustServerCertificate());
            rdpConnectionDetailsDto.setFileTransferMode(rdpConnection.getFileTransferMode());
            rdpConnectionDetailsDto.setMalwareScanningEnabled(rdpConnection.isMalwareScanningEnabled());
            List<RdpConnectionRemoteApplication> remoteApplications = this.genericNativeQueryBasedReadRepository
               .findAll(
                  new NativeQueryBuilder()
                     .from(RdpConnectionRemoteApplication.class, "rcra")
                     .where(QueryAndFilterUtils.foreignKeyFilter("connection_id", connection.getId()))
                     .build()
               );
            if (remoteApplications != null && !remoteApplications.isEmpty()) {
               List<RdpConnectionRemoteApplicationDetailsDto> remoteApplicationDetailsDtoList = remoteApplications.stream()
                  .map(this::convertRdpRemoteApplicationToRdpRemoteApplicationDetailsDto)
                  .collect(Collectors.toList());
               rdpConnectionDetailsDto.setRemoteApplications(remoteApplicationDetailsDtoList);
            }

            return rdpConnectionDetailsDto;
         case SSH:
            SshConnection sshConnection = this.sshConnectionCrudRepository.findOne(SshConnection.class, connection.getId());
            SshConnectionDetailsDto sshConnectionDetailsDto = (SshConnectionDetailsDto)connectionDetailsDto;
            sshConnectionDetailsDto.setColorScheme(sshConnection.getColorScheme());
            sshConnectionDetailsDto.setFontName(sshConnection.getFontName());
            sshConnectionDetailsDto.setFontSize(sshConnection.getFontSize());
            sshConnectionDetailsDto.setFileTransferMode(sshConnection.getFileTransferMode());
            sshConnectionDetailsDto.setMalwareScanningEnabled(sshConnection.isMalwareScanningEnabled());
            sshConnectionDetailsDto.setBastion(sshConnection.isBastion());
            return sshConnectionDetailsDto;
         case VNC:
            VncConnection vncConnection = this.vncConnectionCrudRepository.findOne(VncConnection.class, connection.getId());
            VncConnectionDetailsDto vncConnectionDetailsDto = (VncConnectionDetailsDto)connectionDetailsDto;
            vncConnectionDetailsDto.setClipboardEncoding(vncConnection.getClipboardEncoding());
            vncConnectionDetailsDto.setColorDepth(vncConnection.getColorDepth());
            vncConnectionDetailsDto.setCursorMode(vncConnection.getCursorMode());
            vncConnectionDetailsDto.setReadOnly(vncConnection.isReadOnly());
            vncConnectionDetailsDto.setRepeaterHost(vncConnection.getRepeaterHost());
            vncConnectionDetailsDto.setRepeaterPort(vncConnection.getRepeaterPort());
            vncConnectionDetailsDto.setSwapRedBlue(vncConnection.isSwapRedBlue());
            return vncConnectionDetailsDto;
         case TELNET:
            TelnetConnection telnetConnection = this.telnetConnectionCrudRepository.findOne(TelnetConnection.class, connection.getId());
            TelnetConnectionDetailsDto telnetConnectionDetailsDto = (TelnetConnectionDetailsDto)connectionDetailsDto;
            telnetConnectionDetailsDto.setColorScheme(telnetConnection.getColorScheme());
            telnetConnectionDetailsDto.setFontName(telnetConnection.getFontName());
            telnetConnectionDetailsDto.setFontSize(telnetConnection.getFontSize());
            telnetConnectionDetailsDto.setPasswordRegex(telnetConnection.getPasswordRegex());
            telnetConnectionDetailsDto.setBastion(telnetConnection.isBastion());
            return telnetConnectionDetailsDto;
         default:
            return null;
      }
   }

   private void checkAVScannerServerReachability(ConnectionCreateDto connectionCreateDto) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      if (FileTransferSupportConnectionCreateDto.class.isAssignableFrom(connectionCreateDto.getClass())
         && ((FileTransferSupportConnectionCreateDto)connectionCreateDto).isMalwareScanningEnabled()) {
         this.kavoshIntegrationService.validateIntegration();
      }
   }

   private void copyRdpSpecificParametersToConnection(RdpConnection rdpConnection, RdpConnectionCreateDto rdpConnectionCreateDto) throws RdpRemoteApplicationNameAlreadyExistsException {
      rdpConnection.setAttachConsole(rdpConnectionCreateDto.isAttachConsole());
      rdpConnection.setColorDepth(rdpConnectionCreateDto.getColorDepth());
      rdpConnection.setDisableAudio(rdpConnectionCreateDto.isDisableAudio());
      rdpConnection.setEnableAnimation(rdpConnectionCreateDto.isEnableAnimation());
      rdpConnection.setEnableConsoleAudio(rdpConnectionCreateDto.isEnableConsoleAudio());
      rdpConnection.setEnableFontSmoothing(rdpConnectionCreateDto.isEnableFontSmoothing());
      rdpConnection.setEnablePrinting(rdpConnectionCreateDto.isEnablePrinting());
      rdpConnection.setEnableAudioInput(rdpConnectionCreateDto.isEnableAudioInput());
      rdpConnection.setEnableTheme(rdpConnectionCreateDto.isEnableTheme());
      rdpConnection.setEnableWallpaper(rdpConnectionCreateDto.isEnableWallpaper());
      rdpConnection.setSecurityMode(rdpConnectionCreateDto.getSecurityMode());
      rdpConnection.setStartupAppName(rdpConnectionCreateDto.getStartupAppName());
      rdpConnection.setTrustServerCertificate(rdpConnectionCreateDto.isTrustServerCertificate());
      rdpConnection.setFileTransferMode(rdpConnectionCreateDto.getFileTransferMode());
      rdpConnection.setMalwareScanningEnabled(rdpConnectionCreateDto.isMalwareScanningEnabled());
      if (rdpConnectionCreateDto instanceof RdpConnectionUpdateDto) {
         if (rdpConnectionCreateDto.getRemoteApplications() != null && !rdpConnectionCreateDto.getRemoteApplications().isEmpty()) {
            NativeQuery fetchOldRemoteAppsQuery = new NativeQueryBuilder()
               .from(RdpConnectionRemoteApplication.class, "rcrp")
               .where(QueryAndFilterUtils.foreignKeyFilter("connection_id", rdpConnection.getId()))
               .build();
            List<RdpConnectionRemoteApplication> oldRemoteApps = this.genericNativeQueryBasedReadRepository.findAll(fetchOldRemoteAppsQuery, false);
            List<RdpConnectionRemoteApplication> newRemoteApps = new ArrayList<>();

            for (RdpConnectionRemoteApplicationCreateDto remoteApplicationCreateDto : rdpConnectionCreateDto.getRemoteApplications()) {
               RdpConnectionRemoteApplication rdpConnectionRemoteApplication = new RdpConnectionRemoteApplication();
               rdpConnectionRemoteApplication.setName(remoteApplicationCreateDto.getName());
               rdpConnectionRemoteApplication.setWorkingDirectory(remoteApplicationCreateDto.getWorkingDirectory());
               rdpConnectionRemoteApplication.setParams(remoteApplicationCreateDto.getParams());
               rdpConnectionRemoteApplication.setConnection(rdpConnection);
               if (newRemoteApps.contains(rdpConnectionRemoteApplication)) {
                  throw new RdpRemoteApplicationNameAlreadyExistsException(rdpConnectionCreateDto.getName());
               }

               int index = oldRemoteApps.indexOf(rdpConnectionRemoteApplication);
               if (index != -1) {
                  RdpConnectionRemoteApplication oldRemoteApp = oldRemoteApps.get(index);
                  oldRemoteApp.setName(rdpConnectionRemoteApplication.getName());
                  oldRemoteApp.setWorkingDirectory(rdpConnectionRemoteApplication.getWorkingDirectory());
                  oldRemoteApp.setParams(rdpConnectionRemoteApplication.getParams());
                  this.rdpRemoteApplicationCrudRepository.update(oldRemoteApp);
               }

               newRemoteApps.add(rdpConnectionRemoteApplication);
            }

            List<RdpConnectionRemoteApplication> temp = new ArrayList<>(oldRemoteApps);
            temp.removeAll(newRemoteApps);

            for (RdpConnectionRemoteApplication rdpConnectionRemoteApplicationx : temp) {
               RepositoryContextManager.getUnderlyingEntityManager().remove(rdpConnectionRemoteApplicationx);
               RepositoryContextManager.getUnderlyingEntityManager().flush();
            }

            temp.clear();
            temp.addAll(newRemoteApps);
            temp.removeAll(oldRemoteApps);
            temp.forEach(rdpConnection::addRemoteApplication);
         } else {
            this.rdpRemoteApplicationCrudRepository
               .remove(RdpConnectionRemoteApplication.class, QueryAndFilterUtils.foreignKeyFilter("connection_id", rdpConnection.getId()));
         }
      } else if (rdpConnectionCreateDto.getRemoteApplications() != null && !rdpConnectionCreateDto.getRemoteApplications().isEmpty()) {
         Set<String> names = new HashSet<>();

         for (RdpConnectionRemoteApplicationCreateDto remoteApplicationCreateDto : rdpConnectionCreateDto.getRemoteApplications()) {
            if (!names.add(remoteApplicationCreateDto.getName())) {
               throw new RdpRemoteApplicationNameAlreadyExistsException(remoteApplicationCreateDto.getName());
            }

            RdpConnectionRemoteApplication rdpConnectionRemoteApplicationx = new RdpConnectionRemoteApplication();
            rdpConnectionRemoteApplicationx.setName(remoteApplicationCreateDto.getName());
            rdpConnectionRemoteApplicationx.setWorkingDirectory(remoteApplicationCreateDto.getWorkingDirectory());
            rdpConnectionRemoteApplicationx.setParams(remoteApplicationCreateDto.getParams());
            rdpConnectionRemoteApplicationx.setConnection(rdpConnection);
            rdpConnection.addRemoteApplication(rdpConnectionRemoteApplicationx);
         }
      }
   }

   private void copySshSpecificParametersToConnection(SshConnection sshConnection, SshConnectionCreateDto sshConnectionCreateDto) {
      sshConnection.setColorScheme(sshConnectionCreateDto.getColorScheme());
      sshConnection.setFontName(sshConnectionCreateDto.getFontName());
      sshConnection.setFontSize(sshConnectionCreateDto.getFontSize());
      sshConnection.setFileTransferMode(sshConnectionCreateDto.getFileTransferMode());
      sshConnection.setMalwareScanningEnabled(sshConnectionCreateDto.isMalwareScanningEnabled());
      sshConnection.setBastion(sshConnectionCreateDto.isBastion());
   }

   private void copyVncSpecificParametersToConnection(VncConnection vncConnection, VncConnectionCreateDto vncConnectionCreateDto) {
      vncConnection.setClipboardEncoding(vncConnectionCreateDto.getClipboardEncoding());
      vncConnection.setColorDepth(vncConnectionCreateDto.getColorDepth());
      vncConnection.setCursorMode(vncConnectionCreateDto.getCursorMode());
      vncConnection.setReadOnly(vncConnectionCreateDto.isReadOnly());
      vncConnection.setRepeaterHost(vncConnectionCreateDto.getRepeaterHost());
      vncConnection.setRepeaterPort(vncConnectionCreateDto.getRepeaterPort());
      vncConnection.setSwapRedBlue(vncConnectionCreateDto.isSwapRedBlue());
   }

   private void copyTelnetSpecificParametersToConnection(TelnetConnection telnetConnection, TelnetConnectionCreateDto telnetConnectionCreateDto) {
      telnetConnection.setColorScheme(telnetConnectionCreateDto.getColorScheme());
      telnetConnection.setFontName(telnetConnectionCreateDto.getFontName());
      telnetConnection.setFontSize(telnetConnectionCreateDto.getFontSize());
      telnetConnection.setPasswordRegex(telnetConnectionCreateDto.getPasswordRegex());
      telnetConnection.setBastion(telnetConnectionCreateDto.isBastion());
   }

   private void setAccessibilityTimePeriodConstraintForConnection(
      AccessibilityTimePeriodConstraintCreateDto timePeriodConstraintCreateDto, Connection connection
   ) throws TimePeriodConstraintModeSpecificInfoNotProvidedException {
      AccessibilityTimePeriodConstraint timePeriodConstraint = new AccessibilityTimePeriodConstraint();
      timePeriodConstraint.setMode(timePeriodConstraintCreateDto.getMode());
      timePeriodConstraint.setTimezone(this.authorizationService.getCurrentUserInfo().getTimezone());
      timePeriodConstraint.setConnection(connection);
      connection.setAccessibilityTimePeriodConstraint(timePeriodConstraint);
      switch (timePeriodConstraintCreateDto.getMode()) {
         case DAILY:
            this.setDailyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(timePeriodConstraintCreateDto.getDailyConstraint(), timePeriodConstraint);
            break;
         case WEEKLY:
            if (timePeriodConstraintCreateDto.getWeeklyConstraints() == null || timePeriodConstraintCreateDto.getWeeklyConstraints().isEmpty()) {
               throw new TimePeriodConstraintModeSpecificInfoNotProvidedException();
            }

            this.setWeeklyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
               timePeriodConstraintCreateDto.getWeeklyConstraints(), timePeriodConstraint
            );
            break;
         case MONTHLY:
            if (timePeriodConstraintCreateDto.getMonthlyConstraints() == null || timePeriodConstraintCreateDto.getMonthlyConstraints().isEmpty()) {
               throw new TimePeriodConstraintModeSpecificInfoNotProvidedException();
            }

            this.setMonthlyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
               timePeriodConstraintCreateDto.getMonthlyConstraints(), timePeriodConstraint
            );
      }
   }

   private void setDailyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
      DailyAccessibilityTimePeriodConstraintDto dailyAccessibilityTimePeriodConstraintCreateDto, AccessibilityTimePeriodConstraint timePeriodConstraint
   ) {
      DailyAccessibilityTimePeriodConstraint dailyAccessibilityTimePeriodConstraint = new DailyAccessibilityTimePeriodConstraint();
      dailyAccessibilityTimePeriodConstraint.setFromHour(dailyAccessibilityTimePeriodConstraintCreateDto.getFromHour());
      dailyAccessibilityTimePeriodConstraint.setFromMinute(dailyAccessibilityTimePeriodConstraintCreateDto.getFromMinute());
      dailyAccessibilityTimePeriodConstraint.setToHour(dailyAccessibilityTimePeriodConstraintCreateDto.getToHour());
      dailyAccessibilityTimePeriodConstraint.setToMinute(dailyAccessibilityTimePeriodConstraintCreateDto.getToMinute());
      dailyAccessibilityTimePeriodConstraint.setTimePeriodConstraint(timePeriodConstraint);
      timePeriodConstraint.setDailyConstraint(dailyAccessibilityTimePeriodConstraint);
   }

   private void setWeeklyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
      List<WeeklyAccessibilityTimePeriodConstraintDto> timePeriodWeekDaysCreateDtoList, AccessibilityTimePeriodConstraint timePeriodConstraint
   ) {
      List<WeeklyAccessibilityTimePeriodConstraint> weeklyAccessibilityTimePeriodConstraints = new ArrayList<>();

      for (WeeklyAccessibilityTimePeriodConstraintDto weeklyAccessibilityTimePeriodConstraintDto : timePeriodWeekDaysCreateDtoList) {
         WeeklyAccessibilityTimePeriodConstraint weeklyAccessibilityTimePeriodConstraint = new WeeklyAccessibilityTimePeriodConstraint();
         weeklyAccessibilityTimePeriodConstraint.setWeekDay(weeklyAccessibilityTimePeriodConstraintDto.getWeekDay());
         weeklyAccessibilityTimePeriodConstraint.setFromHour(weeklyAccessibilityTimePeriodConstraintDto.getFromHour());
         weeklyAccessibilityTimePeriodConstraint.setFromMinute(weeklyAccessibilityTimePeriodConstraintDto.getFromMinute());
         weeklyAccessibilityTimePeriodConstraint.setToHour(weeklyAccessibilityTimePeriodConstraintDto.getToHour());
         weeklyAccessibilityTimePeriodConstraint.setToMinute(weeklyAccessibilityTimePeriodConstraintDto.getToMinute());
         weeklyAccessibilityTimePeriodConstraint.setTimePeriodConstraint(timePeriodConstraint);
         weeklyAccessibilityTimePeriodConstraints.add(weeklyAccessibilityTimePeriodConstraint);
      }

      timePeriodConstraint.setWeeklyConstraints(weeklyAccessibilityTimePeriodConstraints);
   }

   private void setMonthlyAccessibilityTimePeriodsToAccessibilityTimePeriodConstraint(
      List<MonthlyAccessibilityTimePeriodConstraintDto> timePeriodMonthDaysCreateDtoList, AccessibilityTimePeriodConstraint timePeriodConstraint
   ) {
      List<MonthlyAccessibilityTimePeriodConstraint> monthlyAccessibilityTimePeriodConstraints = new ArrayList<>();

      for (MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto : timePeriodMonthDaysCreateDtoList) {
         MonthlyAccessibilityTimePeriodConstraint monthlyAccessibilityTimePeriodConstraint = new MonthlyAccessibilityTimePeriodConstraint();
         monthlyAccessibilityTimePeriodConstraint.setMonthDay(monthlyAccessibilityTimePeriodConstraintDto.getMonthDay());
         monthlyAccessibilityTimePeriodConstraint.setFromHour(monthlyAccessibilityTimePeriodConstraintDto.getFromHour());
         monthlyAccessibilityTimePeriodConstraint.setFromMinute(monthlyAccessibilityTimePeriodConstraintDto.getFromMinute());
         monthlyAccessibilityTimePeriodConstraint.setToHour(monthlyAccessibilityTimePeriodConstraintDto.getToHour());
         monthlyAccessibilityTimePeriodConstraint.setToMinute(monthlyAccessibilityTimePeriodConstraintDto.getToMinute());
         monthlyAccessibilityTimePeriodConstraint.setTimePeriodConstraint(timePeriodConstraint);
         monthlyAccessibilityTimePeriodConstraints.add(monthlyAccessibilityTimePeriodConstraint);
      }

      timePeriodConstraint.setMonthlyConstraints(monthlyAccessibilityTimePeriodConstraints);
   }

   private void setSessionInputConstraintsToConnection(
      List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraintCreateDtoList, Connection connection
   ) {
      Set<SessionInputConstraintViolationHandler> sessionInputConstraintHandlers = new HashSet<>();

      for (SessionInputConstraintViolationHandlerCreateDto sessionInputConstraintHandlerCreateDto : sessionInputConstraintCreateDtoList) {
         SessionInputConstraint sessionInputConstraint = this.sessionInputConstraintRepository
            .findOneByRegex(sessionInputConstraintHandlerCreateDto.getConstraintRegex());
         SessionInputConstraintViolationHandler sessionInputConstraintHandler = new SessionInputConstraintViolationHandler();
         sessionInputConstraintHandler.setInputConstraint(sessionInputConstraint);
         sessionInputConstraintHandler.setAlertSomeone(sessionInputConstraintHandlerCreateDto.isAlertSomeone());
         sessionInputConstraintHandler.setPreventExecution(sessionInputConstraintHandlerCreateDto.isPreventExecution());
         sessionInputConstraintHandler.setTerminateSession(sessionInputConstraintHandlerCreateDto.isTerminateSession());
         sessionInputConstraintHandler.setSendNotification(sessionInputConstraintHandlerCreateDto.isSendNotification());
         if (sessionInputConstraintHandler.isAlertSomeone()) {
            sessionInputConstraintHandler.setEmail(sessionInputConstraintHandlerCreateDto.getEmail());
            sessionInputConstraintHandler.setPhoneNumber(sessionInputConstraintHandlerCreateDto.getPhoneNumber());
         }

         sessionInputConstraintHandler.setConnection(connection);
         sessionInputConstraintHandlers.add(sessionInputConstraintHandler);
      }

      connection.setSessionInputConstraints(sessionInputConstraintHandlers);
   }

   private void setBannersToConnection(List<BannerCreateDto> bannerCreateDtoList, Connection connection) {
      Set<Banner> banners = new HashSet<>();

      for (BannerCreateDto bannerCreateDto : bannerCreateDtoList) {
         Banner banner = new Banner();
         banner.setMessage(bannerCreateDto.getMessage());
         banner.setSkippable(bannerCreateDto.isSkippable());
         banner.setConnection(connection);
         banners.add(banner);
      }

      connection.setBanners(banners);
   }

   private void validateCredentialSupportByConnection(CredentialType credentialType, ConnectionType connectionType) throws UnsupportedCredentialTypeByConnectionException {
      if (credentialType.equals(CredentialType.DOMAIN) && !connectionType.equals(ConnectionType.RDP)
         || credentialType.equals(CredentialType.PRIVATE_KEY) && !connectionType.equals(ConnectionType.SSH)) {
         throw new UnsupportedCredentialTypeByConnectionException(credentialType);
      }
   }

   private Credential convertCredentialCreateDtoToCredential(CredentialCreateDto credentialCreateDto, Connection connection) throws UnsupportedCredentialTypeException {
      switch (credentialCreateDto.getType()) {
         case USERNAME_PASSWORD:
            UsernamePasswordCredentialCreateDto usernamePasswordCredentialCreateDto = (UsernamePasswordCredentialCreateDto)credentialCreateDto;
            UsernamePasswordCredential usernamePasswordCredential = new UsernamePasswordCredential();
            usernamePasswordCredential.setType(usernamePasswordCredentialCreateDto.getType());
            usernamePasswordCredential.setLabel(usernamePasswordCredentialCreateDto.getLabel());
            usernamePasswordCredential.setUsername(usernamePasswordCredentialCreateDto.getUsername());
            usernamePasswordCredential.setPassword(usernamePasswordCredentialCreateDto.getPassword());
            usernamePasswordCredential.setConnection(connection);
            return usernamePasswordCredential;
         case DOMAIN:
            DomainCredentialCreateDto domainCredentialCreateDto = (DomainCredentialCreateDto)credentialCreateDto;
            DomainCredential domainCredential = new DomainCredential();
            domainCredential.setType(domainCredentialCreateDto.getType());
            domainCredential.setLabel(domainCredentialCreateDto.getLabel());
            domainCredential.setUsername(domainCredentialCreateDto.getUsername());
            domainCredential.setPassword(domainCredentialCreateDto.getPassword());
            domainCredential.setDomain(domainCredentialCreateDto.getDomain());
            domainCredential.setConnection(connection);
            return domainCredential;
         case PRIVATE_KEY:
            PrivateKeyCredentialCreateDto privateKeyCredentialCreateDto = (PrivateKeyCredentialCreateDto)credentialCreateDto;
            PrivateKeyCredential privateKeyCredential = new PrivateKeyCredential();
            privateKeyCredential.setType(privateKeyCredentialCreateDto.getType());
            privateKeyCredential.setLabel(privateKeyCredentialCreateDto.getLabel());
            privateKeyCredential.setUsername(privateKeyCredentialCreateDto.getUsername());
            privateKeyCredential.setPrivateKey(privateKeyCredentialCreateDto.getPrivateKey());
            privateKeyCredential.setPassphrase(privateKeyCredentialCreateDto.getPassphrase());
            privateKeyCredential.setConnection(connection);
            return privateKeyCredential;
         default:
            throw new UnsupportedCredentialTypeException(credentialCreateDto.getType());
      }
   }

   private void deleteConnectionSpecificType(Connection connection) {
      List<FilterChain> connectionIdFilter = new FilterChainBuilder().filter(new FilterBuilder().number("id").eq(connection.getId()).buildSingle()).build();
      switch (connection.getType()) {
         case RDP:
            this.rdpConnectionCrudRepository.remove(RdpConnection.class, connectionIdFilter);
            break;
         case SSH:
            this.sshConnectionCrudRepository.remove(SshConnection.class, connectionIdFilter);
            break;
         case VNC:
            this.vncConnectionCrudRepository.remove(VncConnection.class, connectionIdFilter);
            break;
         case TELNET:
            this.telnetConnectionCrudRepository.remove(TelnetConnection.class, connectionIdFilter);
            break;
         default:
            throw new SystemInternalErrorException(new IllegalStateException("Unsupported connection type: " + connection.getType()));
      }
   }

   private void checkCaptureRulesAndRemoveIfRequired(Connection connection) {
      JpaQuery<CaptureRule> fetchCaptureRulesSetOverConnectionIndividuallyQuery = new JpaQueryBuilder()
         .from(CaptureRule.class, "cr")
         .join("connections", "c")
         .fetch()
         .build();

      for (CaptureRule captureRule : (Set<CaptureRule>) this.genericJpaQueryBasedReadRepository.findAll(fetchCaptureRulesSetOverConnectionIndividuallyQuery, false)) {
         captureRule.removeConnection(connection);
         if (captureRule.getConnections().isEmpty()) {
            NativeQuery checkIfCaptureRuleHasAnyConnectionGroup = new NativeQueryBuilder()
               .checkExistence()
               .from(ConnectionGroup.class, "cg")
               .joinM2M("tb_capture_rule_connection_group", "crcg", CaptureRule.class, "cr")
               .leftOn("id", "connection_group_id")
               .rightOn("capture_rule_id", "id")
               .joinWhere(QueryAndFilterUtils.idFilter(captureRule.getId()))
               .build();
            if (!this.nativeQueryBasedReadRepository.exists(checkIfCaptureRuleHasAnyConnectionGroup)) {
               this.captureRuleCrudRepository.remove(captureRule);
            }
         }
      }
   }

   private boolean existsByName(String name) {
      return this.nativeQueryBasedReadRepository.exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(Connection.class, "name", name));
   }

   private boolean existsByHostInfo(ConnectionType connectionType, String ipAddress, int port) {
      return this.nativeQueryBasedReadRepository
         .exists(
            new NativeQueryBuilder()
               .checkExistence()
               .from(Connection.class, "con")
               .where(
                  new FilterChainBuilder()
                     .filter(
                        new FilterBuilder()
                           .number("type")
                           .eq(this.typeConverter.convertToDatabaseColumn(connectionType))
                           .and()
                           .string("ip_address")
                           .eq(ipAddress)
                           .and()
                           .number("port")
                           .eq(port)
                           .build()
                     )
                     .build()
               )
               .build()
         );
   }

   private List<FilterChain> connectionFkFilter(Long id) {
      return QueryAndFilterUtils.foreignKeyFilter("connection_id", id);
   }

   private JpaQuery<Connection> fetchConnectionByNameQuery(String name) {
      return new JpaQueryBuilder().from(Connection.class, "c").where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name)).build();
   }

   private JpaQuery<Connection> fetchConnectionWithAllGropsByNameQuery(String name) {
      return new JpaQueryBuilder()
         .from(Connection.class, "c")
         .leftJoin("connectionGroups", "cg")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
   }

   private ConnectionListDto convertTupleToConnectionListDto(Tuple tuple) {
      ConnectionListDto connectionListDto = new ConnectionListDto();
      connectionListDto.setType(this.typeConverter.convertToEntityAttribute(Integer.valueOf(tuple.get("type").toString())));
      if (connectionListDto.getType().equals(ConnectionType.SSH) || connectionListDto.getType().equals(ConnectionType.RDP)) {
         FileTransferMode fileTransferMode = (FileTransferMode) this.genericJpaQueryBasedReadRepository
            .findOne(
               new JpaQueryBuilder()
                  .select("c.fileTransferMode")
                  .from(connectionListDto.getType().equals(ConnectionType.SSH) ? SshConnection.class : RdpConnection.class, "c")
                  .where(QueryAndFilterUtils.idFilter(Long.parseLong(tuple.get("id").toString())))
                  .build(),
               tuple1 -> (FileTransferMode)tuple1.get(0)
            );
         connectionListDto.setFileTransferMode(fileTransferMode);
      }

      connectionListDto.setName((String)tuple.get("name"));
      connectionListDto.setIpAddress((String)tuple.get("ipAddress"));
      connectionListDto.setPort(Integer.valueOf(tuple.get("port").toString()));
      connectionListDto.setClipboard((Boolean)tuple.get("clipboard"));
      AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)connectionListDto);
      return connectionListDto;
   }

   private RdpConnectionRemoteApplicationDetailsDto convertRdpRemoteApplicationToRdpRemoteApplicationDetailsDto(
      RdpConnectionRemoteApplication remoteApplication
   ) {
      RdpConnectionRemoteApplicationDetailsDto remoteApplicationDetailsDto = new RdpConnectionRemoteApplicationDetailsDto();
      remoteApplicationDetailsDto.setName(remoteApplication.getName());
      remoteApplicationDetailsDto.setWorkingDirectory(remoteApplication.getWorkingDirectory());
      remoteApplicationDetailsDto.setParams(remoteApplication.getParams());
      return remoteApplicationDetailsDto;
   }
}
