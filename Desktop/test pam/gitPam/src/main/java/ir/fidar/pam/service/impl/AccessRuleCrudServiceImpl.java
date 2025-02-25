package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.dto.management.notification.ServerEvent;
import ir.fidar.core.domain.dto.management.notification.ServerEventType;
import ir.fidar.core.domain.dto.management.user.UserInfoDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupInfoDto;
import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.SystemConstantsAndDefaults;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.internationalization.MessageResolver;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.service.management.user.UserGroupService;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.AccessRuleRepository;
import ir.fidar.pam.da.repository.CredentialRepository;
import ir.fidar.pam.da.repository.RdpConnectionRemoteApplicationRepository;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.AccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodRepository;
import ir.fidar.pam.domain.dto.BannerCreateDto;
import ir.fidar.pam.domain.dto.BannerDetailsDto;
import ir.fidar.pam.domain.dto.SessionDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerCreateDto;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationHandlerDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintCreateDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.AccessibilityTimePeriodConstraintDetailsDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraintDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleConditionInfoDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleConnectionReadDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleCreateDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleDetailsDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleInfoDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleListDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleUpdateDto;
import ir.fidar.pam.domain.dto.accessrule.ConnectionSpecialSetting;
import ir.fidar.pam.domain.dto.bridge.BridgeInfoDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.dto.connection.RdpConnectionRemoteApplicationDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.CredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.DomainCredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.PrivateKeyCredentialDetailsDto;
import ir.fidar.pam.domain.dto.credential.details.UsernamePasswordCredentialDetailsDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.connection.RdpConnection;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import ir.fidar.pam.domain.model.connection.SshConnection;
import ir.fidar.pam.domain.model.connection.TelnetConnection;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.model.credential.DomainCredential;
import ir.fidar.pam.domain.model.credential.PrivateKeyCredential;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.type.AccessibilityTimePeriodMode;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.domain.type.SessionInteractionType;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.exception.NoUserOrUserGroupProvidedException;
import ir.fidar.pam.exception.TimePeriodConstraintModeSpecificInfoNotProvidedException;
import ir.fidar.pam.exception.accessrule.AccessRuleDisabledException;
import ir.fidar.pam.exception.accessrule.AccessRuleExpiredException;
import ir.fidar.pam.exception.accessrule.AccessRuleIsAlreadyAssignedToUserThroughUserGroupException;
import ir.fidar.pam.exception.accessrule.AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException;
import ir.fidar.pam.exception.accessrule.AccessRuleNameAlreadyExistsException;
import ir.fidar.pam.exception.accessrule.UnsupportedSessionInteractionTypeException;
import ir.fidar.pam.exception.accessrule.UserAlreadyAccessConnectionByAnotherAccessRuleException;
import ir.fidar.pam.exception.accessrule.UserGroupUserAlreadyAccessConnectionByAnotherAccessRuleException;
import ir.fidar.pam.exception.capturerule.NoConnectionOrConnectionGroupIsProvidedException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.BridgeService;
import ir.fidar.pam.service.UserService;
import ir.fidar.pam.service.connection.ConnectionGroupService;
import ir.fidar.pam.service.connection.ConnectionService;
import ir.fidar.pam.session.websocket.RemoteSessionUserCredentialStorageManager;
import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.persistence.Tuple;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AccessRuleCrudServiceImpl extends GlobalCommonServiceImpl<AccessRule> implements AccessRuleCrudService {
   private static final String[] LIST_COLUMNS = new String[]{"ar.name", "ar.clipboard", "ar.fileTransferMode", "ar.disabled", "ar.expirationTime"};
   private final AccessRuleRepository accessRuleRepository;
   private final SessionInputConstraintRepository sessionInputConstraintRepository;
   private final NativeQueryBasedReadRepository nativeReadRepository;
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
   private final ConnectionService connectionService;
   private final ConnectionGroupService connectionGroupService;
   protected final UserService userService;
   private final UserGroupService<UserGroup> userGroupService;
   private final BridgeService bridgeService;
   private final FileTransferModeConverter fileTransferModeConverter;
   private final ConnectionTypeConverter connectionTypeConverter;
   private final CredentialRepository credentialRepository;
   private final RdpConnectionRemoteApplicationRepository rdpConnectionRemoteApplicationRepository;
   private final MessageResolver messageResolver;
   private final NotificationService notificationService;
   private final EmailSender emailSender;
   private final SmsSender smsSender;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private final RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager;

   public AccessRuleCrudServiceImpl(
      AccessRuleRepository accessRuleRepository,
      SessionInputConstraintRepository sessionInputConstraintRepository,
      NativeQueryBasedReadRepository nativeReadRepository,
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
      ConnectionService connectionService,
      ConnectionGroupService connectionGroupService,
      UserService userService,
      UserGroupService<UserGroup> userGroupService,
      BridgeService bridgeService,
      CredentialRepository credentialRepository,
      RdpConnectionRemoteApplicationRepository rdpConnectionRemoteApplicationRepository,
      MessageResolver messageResolver,
      NotificationService notificationService,
      EmailSender emailSender,
      SmsSender smsSender,
      AsyncTaskExecutor asyncTaskExecutor,
      RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager
   ) {
      super(accessRuleRepository);
      this.accessRuleRepository = accessRuleRepository;
      this.sessionInputConstraintRepository = sessionInputConstraintRepository;
      this.nativeReadRepository = nativeReadRepository;
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
      this.connectionService = connectionService;
      this.connectionGroupService = connectionGroupService;
      this.userService = userService;
      this.userGroupService = userGroupService;
      this.bridgeService = bridgeService;
      this.messageResolver = messageResolver;
      this.notificationService = notificationService;
      this.emailSender = emailSender;
      this.smsSender = smsSender;
      this.asyncTaskExecutor = asyncTaskExecutor;
      this.remoteSessionUserCredentialStorageManager = remoteSessionUserCredentialStorageManager;
      this.fileTransferModeConverter = new FileTransferModeConverter();
      this.connectionTypeConverter = new ConnectionTypeConverter();
      this.credentialRepository = credentialRepository;
      this.rdpConnectionRemoteApplicationRepository = rdpConnectionRemoteApplicationRepository;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      NativeQuery fetchAccessRulesQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("ar", LIST_COLUMNS))
         .from(AccessRule.class, "ar")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> accessRuleListDtoList = this.nativeQueryBasedReadRepository
         .findAll(fetchAccessRulesQuery, tuple -> this.convertTupleToAccessRuleListDto(tuple));
      this.setUsersCount(accessRuleListDtoList);
      return Optional.of(accessRuleListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) {
      NativePaginationQuery fetchAccessRulesListByPaginationQuery = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(QueryAndFilterUtils.appendFullAuditionColumns("ar", LIST_COLUMNS))
         .from(AccessRule.class, "ar")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> pageDto = this.nativeQueryBasedReadRepository
         .find(fetchAccessRulesListByPaginationQuery, tuple -> this.convertTupleToAccessRuleListDto(tuple));
      List<ListDto> accessRuleListDtoList = pageDto.getContent();
      this.setUsersCount(accessRuleListDtoList);
      pageDto.setContent(accessRuleListDtoList);
      return Optional.of(pageDto);
   }

   @Transactional(
      readOnly = true
   )
   public Optional<DetailsDto> load(String name) {
      AccessRule accessRule = Optional.ofNullable(this.accessRuleRepository.findOneByNameWithAllConnections(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
      AccessRule accessRuleWithConnectionGroups = this.jpaQueryBasedReadRepository.findOne(this.fetchAccessRuleWithAssociatedConnectionGroups(name));
      AccessRuleDetailsDto accessRuleDetailsDto = new AccessRuleDetailsDto();
      if (accessRule.getConnections() != null) {
         Set<AccessRuleConnectionReadDto> connections = new HashSet<>();

         for (AccessRuleConnection accessRuleConnection : accessRule.getConnections()) {
            AccessRuleConnectionReadDto accessRuleConnectionReadDto = new AccessRuleConnectionReadDto();
            Credential credential = this.credentialRepository
               .findOneByAccessRuleAndConnection(accessRule.getId(), accessRuleConnection.getConnection().getId());
            accessRuleConnectionReadDto.setCredential(this.convertCredentialToCredentialDetailsDto(credential));
            accessRuleConnectionReadDto.setConnection(this.connectionService.convertToInfoDto(accessRuleConnection.getConnection()));
            accessRuleConnectionReadDto.setRemoteApplication(
               this.convertRdpRemoteAppToRdpRemoteAppDetailsDto(accessRuleConnection.getRdpConnectionRemoteApplication())
            );
            connections.add(accessRuleConnectionReadDto);
         }

         accessRuleDetailsDto.setConnections(connections);
      }

      if (accessRuleWithConnectionGroups != null) {
         accessRuleDetailsDto.setConnectionGroups(this.connectionGroupService.convertToInfoDto(accessRuleWithConnectionGroups.getConnectionGroups()));
      }

      List<FilterChain> commonFilter = QueryAndFilterUtils.idFilter(accessRule.getId());
      NativeQuery nativeQuery = new NativeQueryBuilder()
         .select("b.name")
         .from(Bridge.class, "b")
         .join(AccessRule.class, "ar")
         .on("id", "bridge_id")
         .joinWhere(commonFilter)
         .build();
      BridgeInfoDto bridgeInfoDto = this.nativeQueryBasedReadRepository.findOne(nativeQuery, tuple -> {
         BridgeInfoDto infoDto = new BridgeInfoDto();
         infoDto.setName((String)tuple.get("name"));
         return infoDto;
      });
      nativeQuery = new NativeQueryBuilder()
         .select("u.username")
         .from(User.class, "u")
         .distinct()
         .joinM2M("tb_access_rule_user", AccessRule.class, "ar")
         .leftOn("id", "user_id")
         .rightOn("access_rule_id", "id")
         .joinWhere(commonFilter)
         .build();
      List<UserInfoDto> users = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         UserInfoDto infoDto = new UserInfoDto();
         infoDto.setUsername((String)tuple.get("username"));
         return infoDto;
      });
      nativeQuery = new NativeQueryBuilder()
         .select("ug.name")
         .from(UserGroup.class, "ug")
         .distinct()
         .joinM2M("tb_access_rule_user_group", AccessRule.class, "ar")
         .leftOn("id", "user_group_id")
         .rightOn("access_rule_id", "id")
         .joinWhere(commonFilter)
         .build();
      List<UserGroupInfoDto> userGroups = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         UserGroupInfoDto infoDto = new UserGroupInfoDto();
         infoDto.setName((String)tuple.get("name"));
         return infoDto;
      });
      commonFilter = QueryAndFilterUtils.foreignKeyFilter("access_rule_id", accessRule.getId());
      nativeQuery = new NativeQueryBuilder()
         .select("b.message", "b.skippable")
         .from(Banner.class, "b")
         .join(AccessRule.class, "ar")
         .on("access_rule_id", "id")
         .where(commonFilter)
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
         .where(commonFilter)
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
      AccessibilityTimePeriodConstraint timePeriodConstraint = this.accessibilityTimePeriodConstraintRepository.findOneByAccessRuleId(accessRule.getId());
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
               List<MonthlyAccessibilityTimePeriodConstraintDto> monthlyAccessibilityTimePeriodConstraintDtos = new ArrayList<>();

               for (MonthlyAccessibilityTimePeriodConstraint monthlyAccessibilityTimePeriodConstraint : monthlyAccessibilityTimePeriodConstraints) {
                  MonthlyAccessibilityTimePeriodConstraintDto monthlyAccessibilityTimePeriodConstraintDto = new MonthlyAccessibilityTimePeriodConstraintDto();
                  monthlyAccessibilityTimePeriodConstraintDto.setMonthDay(monthlyAccessibilityTimePeriodConstraint.getMonthDay());
                  monthlyAccessibilityTimePeriodConstraintDto.setFromHour(monthlyAccessibilityTimePeriodConstraint.getFromHour());
                  monthlyAccessibilityTimePeriodConstraintDto.setFromMinute(monthlyAccessibilityTimePeriodConstraint.getFromMinute());
                  monthlyAccessibilityTimePeriodConstraintDto.setToHour(monthlyAccessibilityTimePeriodConstraint.getToHour());
                  monthlyAccessibilityTimePeriodConstraintDto.setToMinute(monthlyAccessibilityTimePeriodConstraint.getToMinute());
                  monthlyAccessibilityTimePeriodConstraintDtos.add(monthlyAccessibilityTimePeriodConstraintDto);
               }

               timePeriodConstraintDetailsDto.setMonthlyConstraints(monthlyAccessibilityTimePeriodConstraintDtos);
         }
      }

      accessRuleDetailsDto.setName(accessRule.getName());
      accessRuleDetailsDto.setClipboard(accessRule.isClipboard());
      accessRuleDetailsDto.setFileTransferMode(accessRule.getFileTransferMode());
      accessRuleDetailsDto.setBridge(bridgeInfoDto);
      accessRuleDetailsDto.setUsers(users);
      accessRuleDetailsDto.setUserGroups(userGroups);
      accessRuleDetailsDto.setBanners(banners);
      accessRuleDetailsDto.setAccessibilityTimePeriodConstraint(timePeriodConstraintDetailsDto);
      accessRuleDetailsDto.setSessionInputConstraints(sessionInputConstraints);
      accessRuleDetailsDto.setDisabled(accessRule.isDisabled());
      accessRuleDetailsDto.setOcrEnabled(accessRule.isOcrEnabled());
      accessRuleDetailsDto.setBastion(accessRule.isBastion());
      accessRuleDetailsDto.setExpirationTime(accessRule.getExpirationTime());
      accessRuleDetailsDto.setCaptureDisabled(accessRule.isCaptureDisabled());
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)accessRule, (AbstractDescriptiveDto)accessRuleDetailsDto);
      return Optional.of(accessRuleDetailsDto);
   }

   @Transactional(
      readOnly = true
   )
   public void create(AccessRuleCreateDto accessRuleCreateDto) throws Exception {
      if (this.exists(accessRuleCreateDto.getName())) {
         throw new ResourceAlreadyExistsException(new AccessRuleNameAlreadyExistsException());
      } else {
         this.checkIfAnyUserIsProvided(accessRuleCreateDto);
         this.checkIfAnyConnectionIsProvided(accessRuleCreateDto);
         Set<User> usersToSendNotificationTo = new HashSet<>();
         Set<Connection> totalConnections = new HashSet<>();
         RepositoryContextManager.startNewTransaction();

         try {
            AccessRule accessRule = new AccessRule();
            Bridge bridge = this.bridgeService.getOne(accessRuleCreateDto.getBridge());
            String uuid = UUID.randomUUID().toString();

            while (this.accessRuleRepository.existsByUuid(uuid)) {
               uuid = UUID.randomUUID().toString();
            }

            accessRule.setUuid(uuid);
            accessRule.setName(accessRuleCreateDto.getName());
            accessRule.setBridge(bridge);
            accessRule.setDescription(accessRuleCreateDto.getDescription());
            accessRule.setDisabled(accessRuleCreateDto.isDisabled());
            accessRule.setOcrEnabled(accessRuleCreateDto.isOcrEnabled());
            accessRule.setExpirationTime(accessRuleCreateDto.getExpirationTime());
            accessRule.setCaptureDisabled(accessRuleCreateDto.isCaptureDisabled());
            accessRule.setClipboard(accessRuleCreateDto.isClipboard());
            accessRule.setFileTransferMode(accessRuleCreateDto.getFileTransferMode());
            accessRule.setBastion(accessRuleCreateDto.isBastion());
            this.crudRepository.save(accessRule);
            if (accessRuleCreateDto.getConnectionGroups() != null) {
               for (String connectionGroupName : accessRuleCreateDto.getConnectionGroups()) {
                  ConnectionGroup connectionGroup = this.connectionGroupService.getOneByNameWithAllConnections(connectionGroupName);
                  accessRule.addConnectionGroup(connectionGroup);
                  totalConnections.addAll(connectionGroup.getConnections());
               }
            }

            if (accessRuleCreateDto.getConnections() != null) {
               for (String connectionName : accessRuleCreateDto.getConnections()) {
                  Connection connection = this.connectionService.getOne(connectionName);
                  AccessRuleConnection accessRuleConnection = this.resolveAccessRuleConnection(
                     accessRule, connection, accessRuleCreateDto.getConnectionSpecialSettings()
                  );
                  accessRule.addConnection(accessRuleConnection);
                  totalConnections.add(connection);
               }
            }

            this.crudRepository.update(accessRule);
            if (accessRuleCreateDto.getUserGroups() != null) {
               for (String userGroupName : accessRuleCreateDto.getUserGroups()) {
                  UserGroup userGroup = this.userGroupService.getOneByNameWithAllUsers(userGroupName, true);
                  accessRule.addUserGroup(userGroup);
                  userGroup.getUsers().forEach(userx -> usersToSendNotificationTo.add((User)userx));
               }
            }

            if (accessRuleCreateDto.getUsers() != null) {
               for (String userUsername : accessRuleCreateDto.getUsers()) {
                  User user = this.userService.getOne(userUsername);
                  accessRule.addUser(user);
                  usersToSendNotificationTo.add(user);
               }
            }

            this.crudRepository.update(accessRule);
            this.validateAccessRuleAssignment(accessRule);
            this.validateConnectionUniqueAccessibility(accessRule);
            if (accessRuleCreateDto.getAccessibilityTimePeriodConstraint() != null) {
               this.setAccessibilityTimePeriodConstraintForAccessRule(accessRuleCreateDto.getAccessibilityTimePeriodConstraint(), accessRule);
            }

            if (accessRuleCreateDto.getSessionInputConstraints() != null) {
               this.setSessionInputConstraintsToAccessRule(accessRuleCreateDto.getSessionInputConstraints(), accessRule);
            }

            if (accessRuleCreateDto.getBanners() != null) {
               this.setBannersToAccessRule(accessRuleCreateDto.getBanners(), accessRule);
            }

            this.crudRepository.save(accessRule);
            RepositoryContextManager.commit();
            this.asyncTaskExecutor
               .executeTask(
                  new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(false, usersToSendNotificationTo, totalConnections, accessRule.getName()), true
               );
         } catch (Exception var11) {
            RepositoryContextManager.rollback();
            throw var11;
         }
      }
   }

   @Transactional(
      readOnly = true
   )
   public void update(String name, AccessRuleUpdateDto accessRuleUpdateDto) throws Exception {
      RepositoryContextManager.startNewTransaction();
      AccessRule accessRule = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchAccessRuleWithAssociatedConnection(name), false))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
      if (!accessRuleUpdateDto.getName().equalsIgnoreCase(accessRule.getName()) && this.exists(accessRuleUpdateDto.getName())) {
         throw new ResourceAlreadyExistsException(new AccessRuleNameAlreadyExistsException());
      } else {
         this.checkIfAnyUserIsProvided(accessRuleUpdateDto);
         this.checkIfAnyConnectionIsProvided(accessRuleUpdateDto);
         Set<User> totalOldUsers = this.userService.getAllByAccessRuleId(accessRule.getId());
         Set<Connection> totalOldConnections = this.connectionService.getAllByAccessRuleId(accessRule.getId());
         Set<ir.fidar.core.domain.model.management.User> addedUsers = new HashSet<>();
         Set<ir.fidar.core.domain.model.management.User> removedUsers = new HashSet<>();
         Set<Connection> addedConnections = new HashSet<>();
         Set<Connection> removedConnections = new HashSet<>();

         try {
            Bridge bridge = this.bridgeService.getOne(accessRuleUpdateDto.getBridge());
            accessRule.setName(accessRuleUpdateDto.getName());
            accessRule.setBridge(bridge);
            accessRule.setDescription(accessRuleUpdateDto.getDescription());
            accessRule.setDisabled(accessRuleUpdateDto.isDisabled());
            accessRule.setOcrEnabled(accessRuleUpdateDto.isOcrEnabled());
            accessRule.setExpirationTime(accessRuleUpdateDto.getExpirationTime());
            accessRule.setCaptureDisabled(accessRuleUpdateDto.isCaptureDisabled());
            accessRule.setClipboard(accessRuleUpdateDto.isClipboard());
            accessRule.setFileTransferMode(accessRuleUpdateDto.getFileTransferMode());
            accessRule.setBastion(accessRuleUpdateDto.isBastion());
            if (accessRuleUpdateDto.getConnectionGroups() != null && !accessRuleUpdateDto.getConnectionGroups().isEmpty()) {
               Set<ConnectionGroup> oldConnectionGroups = accessRule.getConnectionGroups();
               Set<ConnectionGroup> newConnectionGroups = new HashSet<>();

               for (String connectionGroupName : accessRuleUpdateDto.getConnectionGroups()) {
                  newConnectionGroups.add(this.connectionGroupService.getOneByNameWithAllConnections(connectionGroupName));
               }

               Set<ConnectionGroup> temp = new HashSet<>(oldConnectionGroups);
               temp.removeAll(newConnectionGroups);

               for (ConnectionGroup deletingConnectionGroup : temp) {
                  accessRule.removeConnectionGroup(deletingConnectionGroup);
                  removedConnections.addAll(deletingConnectionGroup.getConnections());
               }

               temp.clear();
               temp.addAll(newConnectionGroups);
               temp.removeAll(oldConnectionGroups);

               for (ConnectionGroup addingConnectionGroup : temp) {
                  accessRule.addConnectionGroup(addingConnectionGroup);
                  addedConnections.addAll(addingConnectionGroup.getConnections());
               }
            } else {
               accessRule.getConnectionGroups().clear();
            }

            accessRule.getConnections().clear();
            this.crudRepository.update(accessRule);
            if (accessRuleUpdateDto.getConnections() != null) {
               for (String connectionName : accessRuleUpdateDto.getConnections()) {
                  Connection connection = this.connectionService.getOne(connectionName, true);
                  AccessRuleConnection accessRuleConnection = this.resolveAccessRuleConnection(
                     accessRule, connection, accessRuleUpdateDto.getConnectionSpecialSettings()
                  );
                  accessRule.addConnection(accessRuleConnection);
               }
            }

            this.crudRepository.update(accessRule);
            if (accessRuleUpdateDto.getUserGroups() != null && !accessRuleUpdateDto.getUserGroups().isEmpty()) {
               Set<UserGroup> oldUserGroups = accessRule.getUserGroups();
               Set<UserGroup> newUserGroups = new HashSet<>();

               for (String userGroupName : accessRuleUpdateDto.getUserGroups()) {
                  newUserGroups.add(this.userGroupService.getOne(userGroupName));
               }

               Set<UserGroup> temp = new HashSet<>(oldUserGroups);
               temp.removeAll(newUserGroups);

               for (UserGroup deletingUserGroup : temp) {
                  accessRule.removeUserGroup(deletingUserGroup);
                  removedUsers.addAll(deletingUserGroup.getUsers());
               }

               temp.clear();
               temp.addAll(newUserGroups);
               temp.removeAll(oldUserGroups);

               for (UserGroup addingUserGroup : temp) {
                  accessRule.addUserGroup(addingUserGroup);
                  addedUsers.addAll(addingUserGroup.getUsers());
               }
            } else {
               accessRule.getUserGroups().clear();
            }

            if (accessRuleUpdateDto.getUsers() != null && !accessRuleUpdateDto.getUsers().isEmpty()) {
               Set<User> oldUsers = accessRule.getUsers();
               Set<User> newUsers = new HashSet<>();

               for (String userUsername : accessRuleUpdateDto.getUsers()) {
                  newUsers.add(this.userService.getOne(userUsername));
               }

               Set<User> temp = new HashSet<>(oldUsers);
               temp.removeAll(newUsers);

               for (User deletingUser : temp) {
                  accessRule.removeUser(deletingUser);
                  removedUsers.add(deletingUser);
               }

               temp.clear();
               temp.addAll(newUsers);
               temp.removeAll(oldUsers);

               for (User addingUser : temp) {
                  accessRule.addUser(addingUser);
                  addedUsers.add(addingUser);
               }
            } else {
               accessRule.getUsers().clear();
            }

            this.crudRepository.update(accessRule);
            this.validateAccessRuleAssignment(accessRule);
            this.validateConnectionUniqueAccessibility(accessRule);
            List<FilterChain> accessRuleFkFilter = QueryAndFilterUtils.foreignKeyFilter("access_rule_id", accessRule.getId());
            AccessibilityTimePeriodConstraint timePeriodConstraint = accessRule.getAccessibilityTimePeriodConstraint();
            if (accessRuleUpdateDto.getAccessibilityTimePeriodConstraint() == null) {
               if (timePeriodConstraint != null) {
                  accessRule.setAccessibilityTimePeriodConstraint(null);
                  RepositoryContextManager.getUnderlyingEntityManager().remove(timePeriodConstraint);
               }
            } else if (timePeriodConstraint == null) {
               this.setAccessibilityTimePeriodConstraintForAccessRule(accessRuleUpdateDto.getAccessibilityTimePeriodConstraint(), accessRule);
            } else {
               AccessibilityTimePeriodConstraintCreateDto timePeriodConstraintCreateDto = accessRuleUpdateDto.getAccessibilityTimePeriodConstraint();
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
                        dailyAccessibilityTimePeriodConstraint = (DailyAccessibilityTimePeriodConstraint)this.nativeReadRepository
                           .findOne(
                              new NativeQueryBuilder().from(DailyAccessibilityTimePeriodConstraint.class, "datpc").where(timePeriodConstraintIdFilter).build(),
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

                     this.setWeeklyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
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

                     this.setMonthlyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
                        timePeriodConstraintCreateDto.getMonthlyConstraints(), timePeriodConstraint
                     );
               }

               this.accessibilityTimePeriodConstraintCrudRepository.update(timePeriodConstraint);
            }

            this.sessionInputConstraintViolationHandlerCrudRepository.remove(SessionInputConstraintViolationHandler.class, accessRuleFkFilter);
            if (accessRuleUpdateDto.getSessionInputConstraints() != null && !accessRuleUpdateDto.getSessionInputConstraints().isEmpty()) {
               this.setSessionInputConstraintsToAccessRule(accessRuleUpdateDto.getSessionInputConstraints(), accessRule);
            }

            this.bannerCrudRepository.remove(Banner.class, accessRuleFkFilter);
            if (accessRuleUpdateDto.getBanners() != null && !accessRuleUpdateDto.getBanners().isEmpty()) {
               this.setBannersToAccessRule(accessRuleUpdateDto.getBanners(), accessRule);
            }

            this.crudRepository.save(accessRule);
            RepositoryContextManager.commit();
            if (!removedUsers.isEmpty()) {
               this.asyncTaskExecutor
                  .executeTask(new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(true, removedUsers, totalOldConnections, accessRule.getName()), true);
               totalOldUsers.removeAll(removedUsers);
            }

            if (!removedConnections.isEmpty()) {
               this.asyncTaskExecutor
                  .executeTask(new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(true, totalOldUsers, removedConnections, accessRule.getName()), true);
               totalOldConnections.removeAll(removedConnections);
            }

            if (!addedConnections.isEmpty()) {
               this.asyncTaskExecutor
                  .executeTask(new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(false, totalOldUsers, addedConnections, accessRule.getName()), true);
               if (!addedUsers.isEmpty()) {
                  totalOldConnections.addAll(addedConnections);
                  this.asyncTaskExecutor
                     .executeTask(
                        new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(false, addedUsers, new HashSet<>(totalOldConnections), accessRule.getName()),
                        true
                     );
                  totalOldConnections.removeAll(addedConnections);
               }
            } else if (!addedUsers.isEmpty()) {
               this.asyncTaskExecutor
                  .executeTask(new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(false, addedUsers, totalOldConnections, accessRule.getName()), true);
            }
         } catch (Exception var17) {
            RepositoryContextManager.rollback();
            throw var17;
         }
      }
   }

   public void delete(String name) throws Exception {
      JpaQuery<AccessRule> fetchAccessRuleQuery = new JpaQueryBuilder()
         .from(AccessRule.class, "ar")
         .leftJoin("users", "u")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      RepositoryContextManager.startNewTransaction();

      try {
         AccessRule accessRule = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchAccessRuleQuery, false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
         Set<ir.fidar.core.domain.model.management.User> users = new HashSet<>(accessRule.getUsers());

         for (UserGroup userGroup : accessRule.getUserGroups()) {
            users.addAll(userGroup.getUsers());
         }

         Set<Connection> connections = new HashSet<>(accessRule.getConnections().stream().map(AccessRuleConnection::getConnection).collect(Collectors.toList()));

         for (ConnectionGroup connectionGroup : accessRule.getConnectionGroups()) {
            connections.addAll(connectionGroup.getConnections());
         }

         this.crudRepository.remove(accessRule);
         RepositoryContextManager.commit();
         this.asyncTaskExecutor.executeTask(new AccessRuleCrudServiceImpl.SendNotificationToUsersTask(true, users, connections, accessRule.getName()), true);
      } catch (ResourceNotFoundException var8) {
         RepositoryContextManager.rollback();
         throw var8;
      }
   }

   @Transactional(
      readOnly = true
   )
   @Override
   public Optional<CustomPageDto<SessionDto>> loadSessionsOfCurrentUser(Pageable pageable, Sorting sorting, String filter, Set<String> typesFilter) {
      Long currentUserId = this.authorizationService.getCurrentUserInfo().getId();
      long nowEpochSeconds = Instant.now().getEpochSecond();
      List<Long> accessRuleIds = this.accessRuleRepository
         .findAllActivePrivilegeIdsOfUserByUserId(currentUserId, nowEpochSeconds)
         .stream()
         .map(BigInteger::longValue)
         .collect(Collectors.toList());
      if (accessRuleIds.isEmpty()) {
         return Optional.empty();
      } else {
         Set<Integer> filteredTypes = new HashSet<>();
         if (typesFilter != null && !typesFilter.isEmpty()) {
            for (String typeFilter : typesFilter) {
               try {
                  filteredTypes.add(ConnectionType.valueOf(typeFilter).getCode());
               } catch (IllegalArgumentException var24) {
               }
            }
         } else {
            for (ConnectionType connectionType : ConnectionType.values()) {
               filteredTypes.add(connectionType.getCode());
            }
         }

         Tuple totalConnectionsTuple = StringUtils.hasContent(filter)
            ? this.accessRuleRepository.countAllConnectionsByAccessRuleIds(accessRuleIds, filteredTypes, filter)
            : this.accessRuleRepository.countAllConnectionsByAccessRuleIds(accessRuleIds, filteredTypes);
         int offset = pageable.getPageNumber() * pageable.getPageSize();
         long totalDirectConnections = ((Number)totalConnectionsTuple.get("direct_cons_count", Number.class)).longValue();
         long totalGroupedConnections = ((Number)totalConnectionsTuple.get("grouped_cons_count", Number.class)).longValue();
         List<Tuple> connectionTuples;
         if (totalDirectConnections > (long)offset) {
            connectionTuples = StringUtils.hasContent(filter)
               ? this.accessRuleRepository.findAllDirectConnectionsByAccessRuleIds(accessRuleIds, offset, pageable.getPageSize(), filteredTypes, filter)
               : this.accessRuleRepository.findAllDirectConnectionsByAccessRuleIds(accessRuleIds, offset, pageable.getPageSize(), filteredTypes);
            if (connectionTuples.size() < pageable.getPageSize() && totalGroupedConnections > 0L) {
               int var29 = 0;
               int pageSize = pageable.getPageSize() - connectionTuples.size();
               connectionTuples.addAll(
                  StringUtils.hasContent(filter)
                     ? this.accessRuleRepository.findAllGroupedConnectionsByAccessRuleIds(accessRuleIds, var29, pageSize, filteredTypes, filter)
                     : this.accessRuleRepository.findAllGroupedConnectionsByAccessRuleIds(accessRuleIds, var29, pageSize, filteredTypes)
               );
            }
         } else {
            if (totalDirectConnections > 0L) {
               offset = (int)((long)offset - totalDirectConnections);
            }

            connectionTuples = StringUtils.hasContent(filter)
               ? this.accessRuleRepository.findAllGroupedConnectionsByAccessRuleIds(accessRuleIds, offset, pageable.getPageSize(), filteredTypes, filter)
               : this.accessRuleRepository.findAllGroupedConnectionsByAccessRuleIds(accessRuleIds, offset, pageable.getPageSize(), filteredTypes);
         }

         List<SessionDto> sessionDtos = new ArrayList<>();

         for (Tuple connectionTuple : connectionTuples) {
            SessionDto sessionDto = new SessionDto();
            sessionDto.setUuid((String)connectionTuple.get("uuid", String.class));
            sessionDto.setName((String)connectionTuple.get("ar_name", String.class));
            AccessRule accessRule = new AccessRule();
            accessRule.setClipboard((Boolean)connectionTuple.get("ar_clipboard", Boolean.class));
            Connection connection = new Connection();
            connection.setClipboard((Boolean)connectionTuple.get("c_clipboard", Boolean.class));
            sessionDto.setClipboard(this.resolveClipboardStatus(accessRule, connection));
            ConnectionInfoDto connectionInfoDto = new ConnectionInfoDto();
            connectionInfoDto.setName((String)connectionTuple.get("c_name", String.class));
            connectionInfoDto.setType(
               this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)connectionTuple.get("type", Number.class)).intValue()))
            );
            connectionInfoDto.setIpAddress((String)connectionTuple.get("ip_address", String.class));
            connectionInfoDto.setPort(((Number)connectionTuple.get("port", Number.class)).intValue());
            sessionDto.setConnection(connectionInfoDto);
            sessionDtos.add(sessionDto);
         }

         sessionDtos.sort((sessionDto1, sessionDto2) -> {
            String var4x = sorting.getProperty();
            int comparisonResult;
            switch (var4x) {
               case "type":
                  comparisonResult = Integer.compare(sessionDto1.getConnection().getType().getCode(), sessionDto2.getConnection().getType().getCode());
                  break;
               case "connection_name":
                  comparisonResult = sessionDto1.getConnection().getName().compareToIgnoreCase(sessionDto2.getConnection().getName());
                  break;
               case "connection_ip_address":
                  comparisonResult = sessionDto1.getConnection().getIpAddress().compareToIgnoreCase(sessionDto2.getConnection().getIpAddress());
                  break;
               default:
                  comparisonResult = -1;
            }

            return sorting.getOrder().equals(Sorting.Order.ASC) ? comparisonResult : -1 * comparisonResult;
         });
         return Optional.of(
            new CustomPageDto<>(
               sessionDtos,
               totalDirectConnections + totalGroupedConnections,
               (long)Math.ceil(Long.valueOf(totalDirectConnections + totalGroupedConnections).doubleValue() / (double)pageable.getPageSize())
            )
         );
      }
   }

   @Transactional(
      readOnly = true
   )
   @Override
   public Optional<AccessRuleConditionInfoDto> loadConditionInfo(String connectionName) throws InsufficientPrivilegeToAccessSessionException, AccessRuleDisabledException, AccessRuleExpiredException {
      Connection connection = this.connectionService.getOne(connectionName);
      long userId = this.authorizationService.getCurrentUserInfo().getId();
      AccessRule accessRule = Optional.ofNullable(this.accessRuleRepository.findOneByUserIdAndConnectionId(userId, connection.getId()))
         .orElseThrow(InsufficientPrivilegeToAccessSessionException::new);
      if (accessRule.isDisabled()) {
         throw new AccessRuleDisabledException();
      } else if (accessRule.getExpirationTime() != 0L && accessRule.getExpirationTime() <= Instant.now().getEpochSecond()) {
         throw new AccessRuleExpiredException();
      } else {
         AccessRuleConditionInfoDto accessRuleConditionInfoDto = new AccessRuleConditionInfoDto();
         accessRuleConditionInfoDto.setClipboardSupported(this.resolveClipboardStatus(accessRule, connection));
         FileTransferMode fileTransferMode = this.resolveFileTransferMode(accessRule, connection);
         switch (fileTransferMode) {
            case NONE:
               accessRuleConditionInfoDto.setDownloadSupported(false);
               accessRuleConditionInfoDto.setUploadSupported(false);
               break;
            case DOWNLOAD:
               accessRuleConditionInfoDto.setDownloadSupported(true);
               accessRuleConditionInfoDto.setUploadSupported(false);
               break;
            case UPLOAD:
               accessRuleConditionInfoDto.setDownloadSupported(false);
               accessRuleConditionInfoDto.setUploadSupported(true);
               break;
            case BOTH:
               accessRuleConditionInfoDto.setDownloadSupported(true);
               accessRuleConditionInfoDto.setUploadSupported(true);
         }

         accessRuleConditionInfoDto.setCredentialRequired(this.accessRuleRepository.isAnyCredentialSet(accessRule.getId(), connection.getId()) == 0L);
         accessRuleConditionInfoDto.setRememberMeActivated(
            this.remoteSessionUserCredentialStorageManager.exists(this.authorizationService.getCurrentUserInfo().getUsername(), connection)
         );
         ConnectionInfoDto connectionInfoDto = new ConnectionInfoDto();
         connectionInfoDto.setName(connection.getName());
         connectionInfoDto.setIpAddress(connection.getIpAddress());
         connectionInfoDto.setPort(connection.getPort());
         connectionInfoDto.setType(connection.getType());
         accessRuleConditionInfoDto.setConnectionInfo(connectionInfoDto);
         List<BannerDetailsDto> bannerDetailsDtoList = new ArrayList<>();

         for (Banner banner : accessRule.getBanners()) {
            BannerDetailsDto bannerDetailsDto = new BannerDetailsDto();
            bannerDetailsDto.setMessage(banner.getMessage());
            bannerDetailsDto.setSkippable(banner.isSkippable());
            bannerDetailsDtoList.add(bannerDetailsDto);
         }

         for (Banner banner : connection.getBanners()) {
            BannerDetailsDto bannerDetailsDto = new BannerDetailsDto();
            bannerDetailsDto.setMessage(banner.getMessage());
            bannerDetailsDto.setSkippable(banner.isSkippable());
            bannerDetailsDtoList.add(bannerDetailsDto);
         }

         accessRuleConditionInfoDto.setBanners(bannerDetailsDtoList);
         return Optional.of(accessRuleConditionInfoDto);
      }
   }

   @Override
   public Optional<List<InfoDto>> loadAccessRulesAssignedToSpecificUser(String username) {
      User user = this.userService.getOne(username);
      List<Tuple> accessRules = this.accessRuleRepository.findAllAccessRuleOfUserByUserId(user.getId());
      List<InfoDto> accessRuleInfoDtoList = accessRules.stream().map(this::convertTupleToAccessRuleInfoDto).collect(Collectors.toList());
      return Optional.of(accessRuleInfoDtoList);
   }

   @Override
   public Optional<List<InfoDto>> loadAccessRulesAssignedToSpecificUserGroup(String userGroupName) {
      UserGroup userGroup = this.userGroupService.getOne(userGroupName);
      List<Tuple> accessRules = this.accessRuleRepository.findAllAccessRuleOfUserGroupByUserGroupId(userGroup.getId());
      List<InfoDto> accessRuleInfoDtoList = accessRules.stream().map(this::convertTupleToAccessRuleInfoDto).collect(Collectors.toList());
      return Optional.of(accessRuleInfoDtoList);
   }

   @Override
   public Optional<List<InfoDto>> loadAccessRulesSetOverSpecificConnection(String connectionName) {
      Connection connection = this.connectionService.getOne(connectionName);
      List<Tuple> accessRules = this.accessRuleRepository.findAllAccessRuleSetOverConnectionByConnectionId(connection.getId());
      List<InfoDto> accessRuleInfoDtoList = accessRules.stream().map(this::convertTupleToAccessRuleInfoDto).collect(Collectors.toList());
      return Optional.of(accessRuleInfoDtoList);
   }

   @Override
   public Optional<List<InfoDto>> loadAccessRulesSetOverSpecificConnectionGroup(String connectionGroupName) {
      ConnectionGroup connectionGroup = this.connectionGroupService.getOne(connectionGroupName);
      List<Tuple> accessRules = this.accessRuleRepository.findAllAccessRuleSetOverConnectionGroupByConnectionGroupId(connectionGroup.getId());
      List<InfoDto> accessRuleInfoDtoList = accessRules.stream().map(this::convertTupleToAccessRuleInfoDto).collect(Collectors.toList());
      return Optional.of(accessRuleInfoDtoList);
   }

   private void checkIfAnyUserIsProvided(AccessRuleCreateDto accessRuleCreateDto) throws NoUserOrUserGroupProvidedException {
      if ((accessRuleCreateDto.getUsers() == null || accessRuleCreateDto.getUsers().isEmpty())
         && (accessRuleCreateDto.getUserGroups() == null || accessRuleCreateDto.getUserGroups().isEmpty())) {
         throw new NoUserOrUserGroupProvidedException(AccessRule.class);
      }
   }

   private void checkIfAnyConnectionIsProvided(AccessRuleCreateDto accessRuleCreateDto) throws NoConnectionOrConnectionGroupIsProvidedException {
      if ((accessRuleCreateDto.getConnections() == null || accessRuleCreateDto.getConnections().isEmpty())
         && (accessRuleCreateDto.getConnectionGroups() == null || accessRuleCreateDto.getConnectionGroups().isEmpty())) {
         throw new NoConnectionOrConnectionGroupIsProvidedException(AccessRule.class);
      }
   }

   private AccessRuleConnection resolveAccessRuleConnection(
      AccessRule accessRule, Connection connection, Set<ConnectionSpecialSetting> connectionSpecialSettings
   ) {
      AccessRuleConnection accessRuleConnection = new AccessRuleConnection(accessRule, connection);
      if (connectionSpecialSettings != null) {
         for (ConnectionSpecialSetting connectionSpecialSetting : connectionSpecialSettings) {
            if (connectionSpecialSetting.getConnection().equalsIgnoreCase(connection.getName())) {
               if (connectionSpecialSetting.getCredential() != null) {
                  accessRuleConnection.setCredential(
                     this.credentialRepository.findOneByLabelAndConnectionId(connectionSpecialSetting.getCredential(), connection.getId())
                  );
               }

               if (connectionSpecialSetting.getRdpRemoteApplication() != null) {
                  accessRuleConnection.setRdpConnectionRemoteApplication(
                     this.rdpConnectionRemoteApplicationRepository
                        .findOneByNameAndConnectionId(connectionSpecialSetting.getRdpRemoteApplication(), connection.getId())
                  );
               }
               break;
            }
         }
      }

      return accessRuleConnection;
   }

   private AccessRuleListDto convertTupleToAccessRuleListDto(Tuple tuple) {
      AccessRuleListDto accessRuleListDto = new AccessRuleListDto();
      accessRuleListDto.setName((String)tuple.get("name"));
      accessRuleListDto.setClipboard((Boolean)tuple.get("clipboard"));
      accessRuleListDto.setFileTransferMode(this.fileTransferModeConverter.convertToEntityAttribute(Integer.valueOf(tuple.get("fileTransferMode").toString())));
      accessRuleListDto.setDisabled((Boolean)tuple.get("disabled"));
      accessRuleListDto.setExpirationTime(Long.parseLong(tuple.get("expirationTime").toString()));
      AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)accessRuleListDto);
      return accessRuleListDto;
   }

   private void setUsersCount(List<ListDto> accessRuleListDtoList) {
      for (ListDto listDto : accessRuleListDtoList) {
         AccessRuleListDto accessRuleListDto = (AccessRuleListDto)listDto;
         Object[] counts = this.accessRuleRepository.countUsersByName(accessRuleListDto.getName()).get(0);
         accessRuleListDto.setNumberOfUsers(Integer.valueOf(String.valueOf(counts[0])) + Integer.valueOf(String.valueOf(counts[1])));
      }
   }

   protected void validateAccessRuleAssignment(AccessRule accessRule) throws AccessRuleIsAlreadyAssignedToUserThroughUserGroupException, AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException {
      this.validateUserAccessRuleAssignment(accessRule);
      this.validateConnectionAccessRuleAssignment(accessRule);
   }

   protected void validateUserAccessRuleAssignment(AccessRule accessRule) throws AccessRuleIsAlreadyAssignedToUserThroughUserGroupException {
      List<Long> userIds = accessRule.getUsers().stream().map(BaseEntity::getId).collect(Collectors.toList());
      List<Long> userGroupIds = accessRule.getUserGroups().stream().map(BaseEntity::getId).collect(Collectors.toList());
      if (userIds.isEmpty()) {
         userIds.add(0L);
      }

      Tuple tuple = this.accessRuleRepository.validateUsersAndUserGroupsUniqueAssignment(userIds, userGroupIds);
      if (tuple != null) {
         throw new AccessRuleIsAlreadyAssignedToUserThroughUserGroupException(
            (String)tuple.get("username", String.class), (String)tuple.get("ug_name", String.class), (String)tuple.get("u_ug_name", String.class)
         );
      }
   }

   protected void validateConnectionAccessRuleAssignment(AccessRule accessRule) throws AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException {
      List<Long> connectionIds = accessRule.getConnections()
         .stream()
         .map(accessRuleConnection -> accessRuleConnection.getConnection().getId())
         .collect(Collectors.toList());
      List<Long> connectionGroupIds = accessRule.getConnectionGroups().stream().map(BaseEntity::getId).collect(Collectors.toList());
      if (connectionIds.isEmpty()) {
         connectionIds.add(0L);
      }

      Tuple tuple = this.accessRuleRepository.validateConnectionsAndConnectionGroupsUniqueAssignment(connectionIds, connectionGroupIds);
      if (tuple != null) {
         throw new AccessRuleIsAlreadySetOverConnectionThroughConnectionGroupException(
            (String)tuple.get("c_name", String.class), (String)tuple.get("cg_name", String.class), (String)tuple.get("c_cg_name", String.class)
         );
      }
   }

   protected void validateConnectionUniqueAccessibility(AccessRule accessRule) throws AbstractException {
      Tuple tuple = this.accessRuleRepository
         .findConnectionUniqueAccessibilityViolation(
            accessRule.getId(),
            accessRule.getUsers().stream().map(BaseEntity::getId).collect(Collectors.toList()),
            accessRule.getUserGroups().stream().map(BaseEntity::getId).collect(Collectors.toList()),
            accessRule.getConnections().stream().map(accessRuleConnection -> accessRuleConnection.getConnection().getId()).collect(Collectors.toList()),
            accessRule.getConnectionGroups().stream().map(BaseEntity::getId).collect(Collectors.toList())
         );
      if (tuple != null) {
         String userGroup = (String)tuple.get("UG", String.class);
         throw userGroup == null
            ? new UserAlreadyAccessConnectionByAnotherAccessRuleException(
               (String)tuple.get("U", String.class),
               (String)tuple.get("AR", String.class),
               (String)tuple.get("C", String.class),
               (String)tuple.get("CG", String.class)
            )
            : new UserGroupUserAlreadyAccessConnectionByAnotherAccessRuleException(
               (String)tuple.get("U", String.class),
               (String)tuple.get("AR", String.class),
               (String)tuple.get("C", String.class),
               (String)tuple.get("CG", String.class),
               userGroup
            );
      }
   }

   protected boolean resolveClipboardStatus(AccessRule accessRule, Connection connection) {
      return connection.isClipboard() && accessRule.isClipboard();
   }

   protected FileTransferMode resolveFileTransferMode(AccessRule accessRule, Connection connection) {
      FileTransferMode connectionFileTransferMode = this.connectionService.resolveFileTransferMode(connection);
      FileTransferMode accessRuleFileTransferMode = accessRule.getFileTransferMode();
      if (connectionFileTransferMode.equals(accessRuleFileTransferMode) || connectionFileTransferMode.equals(FileTransferMode.BOTH)) {
         return accessRuleFileTransferMode;
      } else {
         return accessRuleFileTransferMode.equals(FileTransferMode.BOTH) ? connectionFileTransferMode : FileTransferMode.NONE;
      }
   }

   protected boolean resolveBastionStatus(AccessRule accessRule, Connection connection) {
      boolean connectionBastion = this.connectionService.resolveBastionStatus(connection);
      return connectionBastion && accessRule.isBastion();
   }

   private void setAccessibilityTimePeriodConstraintForAccessRule(
      AccessibilityTimePeriodConstraintCreateDto timePeriodConstraintCreateDto, AccessRule accessRule
   ) throws TimePeriodConstraintModeSpecificInfoNotProvidedException {
      AccessibilityTimePeriodConstraint timePeriodConstraint = new AccessibilityTimePeriodConstraint();
      timePeriodConstraint.setMode(timePeriodConstraintCreateDto.getMode());
      timePeriodConstraint.setTimezone(this.authorizationService.getCurrentUserInfo().getTimezone());
      timePeriodConstraint.setAccessRule(accessRule);
      accessRule.setAccessibilityTimePeriodConstraint(timePeriodConstraint);
      switch (timePeriodConstraintCreateDto.getMode()) {
         case DAILY:
            this.setDailyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(timePeriodConstraintCreateDto.getDailyConstraint(), timePeriodConstraint);
            break;
         case WEEKLY:
            if (timePeriodConstraintCreateDto.getWeeklyConstraints() == null || timePeriodConstraintCreateDto.getWeeklyConstraints().isEmpty()) {
               throw new TimePeriodConstraintModeSpecificInfoNotProvidedException();
            }

            this.setWeeklyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(timePeriodConstraintCreateDto.getWeeklyConstraints(), timePeriodConstraint);
            break;
         case MONTHLY:
            if (timePeriodConstraintCreateDto.getMonthlyConstraints() == null || timePeriodConstraintCreateDto.getMonthlyConstraints().isEmpty()) {
               throw new TimePeriodConstraintModeSpecificInfoNotProvidedException();
            }

            this.setMonthlyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
               timePeriodConstraintCreateDto.getMonthlyConstraints(), timePeriodConstraint
            );
      }
   }

   private void setDailyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
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

   private void setWeeklyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
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

   private void setMonthlyAccessibilityTimePriodsToAccessibilityTimePeriodConstraint(
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

   private void setSessionInputConstraintsToAccessRule(List<SessionInputConstraintViolationHandlerCreateDto> sessionInputConstraintCreateDtoList, AccessRule accessRule) {
      Set<SessionInputConstraintViolationHandler> sessionInputConstraintHandlers = new HashSet<>();
      for (SessionInputConstraintViolationHandlerCreateDto sessionInputConstraintHandlerCreateDto : sessionInputConstraintCreateDtoList) {
         SessionInputConstraint sessionInputConstraint = (SessionInputConstraint)Optional.<SessionInputConstraint>ofNullable(this.sessionInputConstraintRepository.findOneByRegex(sessionInputConstraintHandlerCreateDto.getConstraintRegex())).orElseThrow(() -> new ResourceNotFoundException((Exception)new EntityNotFoundException(SessionInputConstraint.class)));
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
         sessionInputConstraintHandler.setAccessRule(accessRule);
         sessionInputConstraintHandlers.add(sessionInputConstraintHandler);
      }
      accessRule.setSessionInputConstraints(sessionInputConstraintHandlers);
   }

   private void setBannersToAccessRule(List<BannerCreateDto> bannerCreateDtoList, AccessRule accessRule) {
      Set<Banner> banners = new HashSet<>();

      for (BannerCreateDto bannerCreateDto : bannerCreateDtoList) {
         Banner banner = new Banner();
         banner.setMessage(bannerCreateDto.getMessage());
         banner.setSkippable(bannerCreateDto.isSkippable());
         banner.setAccessRule(accessRule);
         banners.add(banner);
      }

      accessRule.setBanners(banners);
   }

   private void setFileTransferInteractionIfSupported(
      FileTransferMode connectionFileTransferMode, FileTransferMode accessRuleDtoFileTransferMode, AccessRule targetAccessRule
   ) throws UnsupportedSessionInteractionTypeException {
      switch (connectionFileTransferMode) {
         case NONE:
            if (!accessRuleDtoFileTransferMode.equals(FileTransferMode.NONE)) {
               throw new UnsupportedSessionInteractionTypeException(SessionInteractionType.FILE_TRANSFER);
            }

            targetAccessRule.setFileTransferMode(accessRuleDtoFileTransferMode);
            break;
         case DOWNLOAD:
            if (!accessRuleDtoFileTransferMode.equals(FileTransferMode.DOWNLOAD) && !accessRuleDtoFileTransferMode.equals(FileTransferMode.NONE)) {
               throw new UnsupportedSessionInteractionTypeException(SessionInteractionType.FILE_TRANSFER);
            }

            targetAccessRule.setFileTransferMode(accessRuleDtoFileTransferMode);
            break;
         case UPLOAD:
            if (!accessRuleDtoFileTransferMode.equals(FileTransferMode.UPLOAD) && !accessRuleDtoFileTransferMode.equals(FileTransferMode.NONE)) {
               throw new UnsupportedSessionInteractionTypeException(SessionInteractionType.FILE_TRANSFER);
            }

            targetAccessRule.setFileTransferMode(accessRuleDtoFileTransferMode);
            break;
         case BOTH:
            targetAccessRule.setFileTransferMode(accessRuleDtoFileTransferMode);
      }
   }

   private JpaQuery fetchConnectionFileTransferModeQuery(ConnectionType connectionType, Long connectionId) {
      return new JpaQueryBuilder()
         .select("c.fileTransferMode")
         .from(connectionType.equals(ConnectionType.SSH) ? SshConnection.class : RdpConnection.class, "c")
         .where(QueryAndFilterUtils.idFilter(connectionId))
         .build();
   }

   private JpaQuery fetchConnectionBastionQuery(ConnectionType connectionType, Long connectionId) {
      return new JpaQueryBuilder()
         .select("c.bastion")
         .from(connectionType.equals(ConnectionType.SSH) ? SshConnection.class : TelnetConnection.class, "c")
         .where(QueryAndFilterUtils.idFilter(connectionId))
         .build();
   }

   private boolean exists(String name) {
      return this.nativeQueryBasedReadRepository.exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(AccessRule.class, "name", name));
   }

   private JpaQuery<AccessRule> fetchAccessRuleWithAssociatedConnection(String name) {
      return new JpaQueryBuilder()
         .from(AccessRule.class, "ar")
         .leftJoin("connections", "ar_c")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
   }

   private JpaQuery<AccessRule> fetchAccessRuleWithAssociatedConnectionGroups(String name) {
      return new JpaQueryBuilder()
         .from(AccessRule.class, "ar")
         .join("connectionGroups", "cg")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
   }

   private CredentialDetailsDto convertCredentialToCredentialDetailsDto(Credential credential) {
      if (credential != null) {
         CredentialDetailsDto credentialDetailsDto = null;
         switch (credential.getType()) {
            case USERNAME_PASSWORD:
               UsernamePasswordCredential usernamePasswordCredential = this.credentialRepository.findUsernamePasswordCredentialById(credential.getId());
               UsernamePasswordCredentialDetailsDto usernamePasswordCredentialDetailsDto = new UsernamePasswordCredentialDetailsDto();
               usernamePasswordCredentialDetailsDto.setType(usernamePasswordCredential.getType());
               usernamePasswordCredentialDetailsDto.setLabel(usernamePasswordCredential.getLabel());
               usernamePasswordCredentialDetailsDto.setUsername(usernamePasswordCredential.getUsername());
               credentialDetailsDto = usernamePasswordCredentialDetailsDto;
               break;
            case DOMAIN:
               DomainCredential domainCredential = this.credentialRepository.findDomainCredentialById(credential.getId());
               DomainCredentialDetailsDto domainCredentialDetailsDto = new DomainCredentialDetailsDto();
               domainCredentialDetailsDto.setType(domainCredential.getType());
               domainCredentialDetailsDto.setLabel(domainCredential.getLabel());
               domainCredentialDetailsDto.setDomain(domainCredential.getDomain());
               domainCredentialDetailsDto.setUsername(domainCredential.getUsername());
               credentialDetailsDto = domainCredentialDetailsDto;
               break;
            case PRIVATE_KEY:
               PrivateKeyCredential privateKeyCredential = this.credentialRepository.findPrivateKeyCredentialById(credential.getId());
               PrivateKeyCredentialDetailsDto privateKeyCredentialDetailsDto = new PrivateKeyCredentialDetailsDto();
               privateKeyCredentialDetailsDto.setType(privateKeyCredential.getType());
               privateKeyCredentialDetailsDto.setLabel(privateKeyCredential.getLabel());
               privateKeyCredentialDetailsDto.setUsername(privateKeyCredential.getUsername());
               credentialDetailsDto = privateKeyCredentialDetailsDto;
         }

         return credentialDetailsDto;
      } else {
         return null;
      }
   }

   private RdpConnectionRemoteApplicationDetailsDto convertRdpRemoteAppToRdpRemoteAppDetailsDto(RdpConnectionRemoteApplication rdpConnectionRemoteApplication) {
      if (rdpConnectionRemoteApplication != null) {
         RdpConnectionRemoteApplicationDetailsDto remoteApplicationDetailsDto = new RdpConnectionRemoteApplicationDetailsDto();
         remoteApplicationDetailsDto.setName(rdpConnectionRemoteApplication.getName());
         remoteApplicationDetailsDto.setWorkingDirectory(rdpConnectionRemoteApplication.getWorkingDirectory());
         remoteApplicationDetailsDto.setParams(rdpConnectionRemoteApplication.getParams());
         return remoteApplicationDetailsDto;
      } else {
         return null;
      }
   }

   private AccessRuleInfoDto convertTupleToAccessRuleInfoDto(Tuple tuple) {
      AccessRuleInfoDto accessRuleInfoDto = new AccessRuleInfoDto();
      accessRuleInfoDto.setName((String)tuple.get("AR_NAME", String.class));
      accessRuleInfoDto.setConnectionName((String)tuple.get("name", String.class));
      accessRuleInfoDto.setIpAddress((String)tuple.get("ip_address", String.class));
      accessRuleInfoDto.setPort(((Number)tuple.get("port", Number.class)).intValue());
      accessRuleInfoDto.setType(this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue())));
      AccessRule accessRule = new AccessRule();
      accessRule.setClipboard((Boolean)tuple.get("AR_clipboard", Boolean.class));
      Connection connection = new Connection();
      connection.setClipboard((Boolean)tuple.get("clipboard", Boolean.class));
      accessRuleInfoDto.setClipboard(this.resolveClipboardStatus(accessRule, connection));
      return accessRuleInfoDto;
   }

   private class SendNotificationToUsersTask implements Runnable {
      private static final String ACCESS_ASSIGNED_SUBJECT_CODE = "access_rule.assigned_access_rule.message.subject";
      private static final String ACCESS_ASSIGNED_MESSAGE_SINGLE_CODE = "access_rule.assigned_access_rule.message.single";
      private static final String ACCESS_ASSIGNED_MESSAGE_MULTIPLE_CODE = "access_rule.assigned_access_rule.message.multiple";
      private static final String ACCESS_ASSIGNED_MESSAGE_EXTRA_CODE = "access_rule.assigned_access_rule.message.multiple_extra";
      private static final String ACCESS_REVOKED_SUBJECT_CODE = "access_rule.revoked_access_rule.message.subject";
      private static final String ACCESS_REVOKED_MESSAGE_SINGLE_CODE = "access_rule.revoked_access_rule.message.single";
      private static final String ACCESS_REVOKED_MESSAGE_MULTIPLE_CODE = "access_rule.revoked_access_rule.message.multiple";
      private static final String ACCESS_REVOKED_MESSAGE_EXTRA_CODE = "access_rule.revoked_access_rule.message.multiple_extra";
      private final boolean accessRevoked;
      private final Set<? extends ir.fidar.core.domain.model.management.User> users;
      private final Set<Connection> connections;
      private final String accessRuleName;

      private SendNotificationToUsersTask(
         boolean accessRevoked, Set<? extends ir.fidar.core.domain.model.management.User> users, Set<Connection> connections, String accessRuleName
      ) {
         this.users = users;
         this.connections = connections;
         this.accessRuleName = accessRuleName;
         this.accessRevoked = accessRevoked;
      }

      @Override
      public void run() {
         if (this.users != null && !this.users.isEmpty() && this.connections != null && !this.connections.isEmpty()) {
            StringBuilder hostBuilder = new StringBuilder();
            int extraConnectionsCount = this.connections.size() - 3;
            Iterator<Connection> connectionIterator = this.connections.iterator();
            if (this.connections.size() == 1) {
               Connection connection = connectionIterator.next();
               hostBuilder.append(String.format("%s:%d", connection.getIpAddress(), connection.getPort()));
            } else {
               for (int i = 0; connectionIterator.hasNext() && i < 3; i++) {
                  Connection connection = connectionIterator.next();
                  hostBuilder.append(String.format("'%s:%d'", connection.getIpAddress(), connection.getPort())).append(", ");
               }

               hostBuilder.delete(hostBuilder.length() - 2, hostBuilder.length());
            }

            String targetCode = this.accessRevoked ? "access_rule.revoked_access_rule.message.single" : "access_rule.assigned_access_rule.message.single";
            if (this.connections.size() > 1 && this.connections.size() <= 3) {
               targetCode = this.accessRevoked ? "access_rule.revoked_access_rule.message.multiple" : "access_rule.assigned_access_rule.message.multiple";
            } else if (this.connections.size() > 3) {
               targetCode = this.accessRevoked
                  ? "access_rule.revoked_access_rule.message.multiple_extra"
                  : "access_rule.assigned_access_rule.message.multiple_extra";
            }

            String[] args;
            if (this.accessRevoked) {
               args = new String[targetCode.equals("access_rule.revoked_access_rule.message.multiple_extra") ? 2 : 1];
               args[0] = hostBuilder.toString();
               if (targetCode.equals("access_rule.revoked_access_rule.message.multiple_extra")) {
                  args[1] = String.valueOf(extraConnectionsCount);
               }
            } else {
               args = new String[targetCode.equals("access_rule.assigned_access_rule.message.multiple_extra") ? 3 : 2];
               args[0] = hostBuilder.toString();
               if (targetCode.equals("access_rule.assigned_access_rule.message.multiple_extra")) {
                  args[1] = String.valueOf(extraConnectionsCount);
                  args[2] = this.accessRuleName;
               } else {
                  args[1] = this.accessRuleName;
               }
            }

            Map<String, String> messagePerLocale = new HashMap<>();
            Map<String, String> subjectPerLocale = new HashMap<>();

            for (ir.fidar.core.domain.model.management.User user : this.users) {
               Locale locale = new Locale(user.getLocale());
               if (Thread.interrupted()) {
                  break;
               }

               String finalTargetCode = targetCode;
               String message = messagePerLocale.computeIfAbsent(
                  user.getLocale(), s -> AccessRuleCrudServiceImpl.this.messageResolver.getMessage(finalTargetCode, locale, args)
               );

               try {
                  AccessRuleCrudServiceImpl.this.notificationService
                     .broadCastMessage(
                        new ServerEvent(ServerEventType.MESSAGE, message, SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()),
                        Stream.of(user.getUsername()).collect(Collectors.toSet()),
                        true
                     );
               } catch (Exception var17) {
               }

               String subject = subjectPerLocale.computeIfAbsent(
                  user.getLocale(),
                  k -> AccessRuleCrudServiceImpl.this.messageResolver
                        .getMessage(
                           this.accessRevoked ? "access_rule.revoked_access_rule.message.subject" : "access_rule.assigned_access_rule.message.subject", locale
                        )
               );
               if (StringUtils.hasContent(user.getEmail())) {
                  try {
                     AccessRuleCrudServiceImpl.this.emailSender.send(user.getEmail(), subject, message);
                  } catch (Exception var16) {
                  }
               }

               if (StringUtils.hasContent(user.getPhoneNumber())) {
                  try {
                     String titledMessage = String.format("%s %s", subject, message);
                     AccessRuleCrudServiceImpl.this.smsSender.send(user.getPhoneNumber(), titledMessage);
                  } catch (Exception var15) {
                  }
               }
            }
         }
      }
   }
}
