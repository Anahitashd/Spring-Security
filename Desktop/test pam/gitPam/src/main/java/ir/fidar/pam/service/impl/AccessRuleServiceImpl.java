package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.domain.model.BaseEntity;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.internationalization.MessageResolver;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.service.management.user.UserGroupService;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.da.repository.AccessRuleConnectionRepository;
import ir.fidar.pam.da.repository.AccessRuleRepository;
import ir.fidar.pam.da.repository.CredentialRepository;
import ir.fidar.pam.da.repository.RdpConnectionRemoteApplicationRepository;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.AccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraintRepository;
import ir.fidar.pam.da.repository.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodRepository;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleCreateDto;
import ir.fidar.pam.domain.dto.accessrule.ConnectionSpecialSetting;
import ir.fidar.pam.domain.dto.connection.ConnectionSessionInteractionModeDto;
import ir.fidar.pam.domain.model.Banner;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.AccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.DailyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.MonthlyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessibilitytimeperiod.WeeklyAccessibilityTimePeriodConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnectionId;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingRuleAssignmentException;
import ir.fidar.pam.exception.UserUserGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.UserUserGroupAssignmentViolatingRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.connection.ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.BridgeService;
import ir.fidar.pam.service.UserService;
import ir.fidar.pam.service.connection.ConnectionGroupService;
import ir.fidar.pam.service.connection.ConnectionService;
import ir.fidar.pam.session.websocket.RemoteSessionUserCredentialStorageManager;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.persistence.Tuple;
import org.springframework.stereotype.Service;

@Service
public class AccessRuleServiceImpl extends AccessRuleCrudServiceImpl implements AccessRuleService {
   private final AccessRuleRepository accessRuleRepository;
   private final BridgeService bridgeService;
   private final AccessRuleConnectionRepository accessRuleConnectionRepository;
   private final ConnectionService connectionService;

   public AccessRuleServiceImpl(
      AccessRuleRepository accessRuleRepository,
      SessionInputConstraintRepository sessionInputConstraintRepository,
      NativeQueryBasedReadRepository accessibilityTimePeriodConstraintReadRepository,
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
      RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager,
      AccessRuleConnectionRepository accessRuleConnectionRepository
   ) {
      super(
         accessRuleRepository,
         sessionInputConstraintRepository,
         accessibilityTimePeriodConstraintReadRepository,
         accessibilityTimePeriodConstraintRepository,
         accessibilityTimePeriodConstraintCrudRepository,
         dailyAccessibilityTimePeriodConstraintRepository,
         dailyAccessibilityTimePeriodConstraintCrudRepository,
         weeklyAccessibilityTimePeriodRepository,
         weeklyAccessibilityTimePeriodConstraintCrudRepository,
         monthlyAccessibilityTimePeriodConstraintRepository,
         monthlyAccessibilityTimePeriodConstraintCrudRepository,
         sessionInputConstraintViolationHandlerCrudRepository,
         bannerCrudRepository,
         connectionService,
         connectionGroupService,
         userService,
         userGroupService,
         bridgeService,
         credentialRepository,
         rdpConnectionRemoteApplicationRepository,
         messageResolver,
         notificationService,
         emailSender,
         smsSender,
         asyncTaskExecutor,
         remoteSessionUserCredentialStorageManager
      );
      this.accessRuleRepository = accessRuleRepository;
      this.bridgeService = bridgeService;
      this.accessRuleConnectionRepository = accessRuleConnectionRepository;
      this.connectionService = connectionService;
   }

   @Override
   public List<AccessRule> getAll() {
      return this.accessRuleRepository.findAll();
   }

   public AccessRule getOne(String name) {
      return Optional.ofNullable(this.accessRuleRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
   }

   public AccessRule getOne(Long id) {
      return Optional.ofNullable(this.accessRuleRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
   }

   @Override
   public AccessRule getOneByName(String name, boolean readOnly) {
      JpaQuery<AccessRule> fetchByTitleQuery = new JpaQueryBuilder()
         .from(AccessRule.class, "ar")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      return Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchByTitleQuery, readOnly))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
   }

   @Override
   public AccessRule getOneByUuid(String uuid) {
      return Optional.ofNullable(this.accessRuleRepository.findOneByUuid(uuid))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
   }

   @Override
   public void addUser(String name, User user) throws AbstractException {
      RepositoryContextManager.startNewTransaction();

      try {
         AccessRule accessRule = this.getOneByName(name, false);
         accessRule.addUser(user);
         this.crudRepository.update(accessRule);
         this.validateAccessRuleAssignment(accessRule);
      } catch (Exception var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   @Override
   public void createNewRecord(
      String name,
      String connectionName,
      String credentialLabel,
      Set<String> users,
      Set<String> userGroups,
      boolean clipboardEnabled,
      FileTransferMode fileTransferMode
   ) throws Exception {
      AccessRuleCreateDto accessRuleCreateDto = new AccessRuleCreateDto();
      accessRuleCreateDto.setName(name);
      accessRuleCreateDto.setConnections(Collections.singleton(connectionName));
      ConnectionSpecialSetting connectionSpecialSetting = new ConnectionSpecialSetting();
      connectionSpecialSetting.setConnection(connectionName);
      connectionSpecialSetting.setCredential(credentialLabel);
      accessRuleCreateDto.setConnectionSpecialSettings(Collections.singleton(connectionSpecialSetting));
      accessRuleCreateDto.setUsers(users);
      accessRuleCreateDto.setUserGroups(userGroups);
      accessRuleCreateDto.setClipboard(clipboardEnabled);
      accessRuleCreateDto.setFileTransferMode(fileTransferMode);
      accessRuleCreateDto.setBridge(this.bridgeService.getAll().get(0).getName());
      create(accessRuleCreateDto);
   }

   @Override
   public void delete(Long id) {
      this.crudRepository.remove(AccessRule.class, QueryAndFilterUtils.idFilter(id));
   }

   @Override
   public AccessRule getOneByUserAndConnection(long userId, long connectionId) {
      return Optional.ofNullable(this.accessRuleRepository.findOneByUserIdAndConnectionId(userId, connectionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(AccessRule.class)));
   }

   @Override
   public AccessRuleConnection getConnectionSettings(Long accessRuleId, Long connectionId) {
      return this.accessRuleConnectionRepository.findOneById(new AccessRuleConnectionId(accessRuleId, connectionId));
   }

   @Override
   public ConnectionSessionInteractionModeDto resolveInteractionSettings(AccessRule accessRule, Connection connection) {
      ConnectionSessionInteractionModeDto interactionModeDto = new ConnectionSessionInteractionModeDto();
      interactionModeDto.setClipboard(super.resolveClipboardStatus(accessRule, connection));
      interactionModeDto.setFileTransferMode(super.resolveFileTransferMode(accessRule, connection));
      interactionModeDto.setBastion(super.resolveBastionStatus(accessRule, connection));
      return interactionModeDto;
   }

   @Override
   public void validateUserGroupUserMembership(UserGroup userGroup) throws UserGroupUserMembershipViolatingRuleAssignmentException, UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException {
      List<Long> userIds = userGroup.getUsers().stream().map(BaseEntity::getId).collect(Collectors.toList());
      Tuple tuple = this.accessRuleRepository.findAccessRuleAssignmentViolationForUserGroupUserMembership(userGroup.getId(), userIds);
      if (tuple != null) {
         throw new UserGroupUserMembershipViolatingRuleAssignmentException(
            (String)tuple.get("username", String.class),
            (String)tuple.get("ar_name", String.class),
            AccessRule.class,
            (String)tuple.get("ug_name", String.class)
         );
      } else {
         tuple = this.accessRuleRepository.findConnectionUniqueAccessibilityViolationForUserGroupUserMembership(userGroup.getId(), userIds);
         if (tuple != null) {
            throw new UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException(
               (String)tuple.get("c_name", String.class),
               (String)tuple.get("username", String.class),
               (String)tuple.get("user_ug_name", String.class),
               (String)tuple.get("user_ar_name", String.class),
               (String)tuple.get("user_cg_name", String.class),
               (String)tuple.get("ug_ar_name", String.class),
               (String)tuple.get("ug_cg_name", String.class)
            );
         }
      }
   }

   @Override
   public void validateUserUserGroupAssignment(User user) throws UserUserGroupAssignmentViolatingRuleAssignmentException, UserUserGroupAssignmentViolatingAccessRuleConnectionAccessibilityException {
      List<Long> userGroupIds = user.getUserGroups().stream().map(BaseEntity::getId).collect(Collectors.toList());
      Tuple tuple = this.accessRuleRepository.findAccessRuleAssignmentViolationForUserUserGroupAssignment(user.getId(), userGroupIds);
      if (tuple != null) {
         throw new UserUserGroupAssignmentViolatingRuleAssignmentException(
            (String)tuple.get("ug_name", String.class),
            (String)tuple.get("ar_name", String.class),
            AccessRule.class,
            (String)tuple.get("u_ug_name", String.class)
         );
      } else {
         tuple = this.accessRuleRepository.findConnectionUniqueAccessibilityViolationForUserUserGroupAssignment(user.getId(), userGroupIds);
         if (tuple != null) {
            throw new UserUserGroupAssignmentViolatingAccessRuleConnectionAccessibilityException(
               (String)tuple.get("c_name", String.class),
               (String)tuple.get("ug_name", String.class),
               (String)tuple.get("user_ug_name", String.class),
               (String)tuple.get("user_ar_name", String.class),
               (String)tuple.get("user_cg_name", String.class),
               (String)tuple.get("ug_ar_name", String.class),
               (String)tuple.get("ug_cg_name", String.class)
            );
         }
      }
   }

   @Override
   public void validateConnectionGroupConnectionMembership(ConnectionGroup connectionGroup) throws ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException, ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException {
      List<Long> connectionIds = connectionGroup.getConnections().stream().map(BaseEntity::getId).collect(Collectors.toList());
      Tuple tuple = this.accessRuleRepository.findAccessRuleAssignmentViolationForConnectionGroupConnectionMembership(connectionGroup.getId(), connectionIds);
      if (tuple != null) {
         throw new ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException(
            (String)tuple.get("c_name", String.class), (String)tuple.get("ar_name", String.class), (String)tuple.get("c_cg_name", String.class)
         );
      } else {
         tuple = this.accessRuleRepository
            .findConnectionUniqueAccessibilityViolationForConnectionGroupConnectionMembership(connectionGroup.getId(), connectionIds);
         if (tuple != null) {
            throw new ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException(
               (String)tuple.get("user", String.class),
               (String)tuple.get("c_name", String.class),
               (String)tuple.get("c_cg_name", String.class),
               (String)tuple.get("c_ar_name", String.class),
               (String)tuple.get("c_u_ug", String.class),
               (String)tuple.get("cg_ar_name", String.class),
               (String)tuple.get("cg_u_ug", String.class)
            );
         }
      }
   }

   @Override
   public void validateConnectionConnectionGroupAssignment(Connection connection) throws ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException, ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException {
      List<Long> connectionGroupIds = connection.getConnectionGroups().stream().map(BaseEntity::getId).collect(Collectors.toList());
      Tuple tuple = this.accessRuleRepository.findAccessRuleAssignmentViolationForConnectionConnectionGroupAssignment(connection.getId(), connectionGroupIds);
      if (tuple != null) {
         throw new ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException(
            (String)tuple.get("cg_name", String.class), (String)tuple.get("ar_name", String.class), (String)tuple.get("c_cg_name", String.class)
         );
      } else {
         tuple = this.accessRuleRepository
            .findConnectionUniqueAccessibilityViolationForConnectionConnectionGroupAssignment(connection.getId(), connectionGroupIds);
         if (tuple != null) {
            throw new ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException(
               (String)tuple.get("user", String.class),
               (String)tuple.get("cg_name", String.class),
               (String)tuple.get("c_cg_name", String.class),
               (String)tuple.get("c_ar_name", String.class),
               (String)tuple.get("c_u_ug", String.class),
               (String)tuple.get("cg_ar_name", String.class),
               (String)tuple.get("cg_u_ug", String.class)
            );
         }
      }
   }
}
