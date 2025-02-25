package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.dto.management.user.UserInfoDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupInfoDto;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.service.management.user.UserGroupService;
import ir.fidar.core.service.management.user.UserService;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.CaptureRuleRepository;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleCreateDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleDetailsDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleInfoDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleListDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleUpdateDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.exception.NoUserOrUserGroupProvidedException;
import ir.fidar.pam.exception.capturerule.CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException;
import ir.fidar.pam.exception.capturerule.CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException;
import ir.fidar.pam.exception.capturerule.CaptureRuleNameAlreadyExists;
import ir.fidar.pam.exception.capturerule.NoConnectionOrConnectionGroupIsProvidedException;
import ir.fidar.pam.exception.capturerule.UserAlreadyAccessConnectionByAnotherCaptureRuleException;
import ir.fidar.pam.exception.capturerule.UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException;
import ir.fidar.pam.exception.capturerule.UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException;
import ir.fidar.pam.exception.capturerule.UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException;
import ir.fidar.pam.exception.capturerule.UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException;
import ir.fidar.pam.service.CaptureRuleCrudService;
import ir.fidar.pam.service.connection.ConnectionGroupService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.persistence.Tuple;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class CaptureRuleCrudServiceImpl extends GlobalCommonServiceImpl<CaptureRule> implements CaptureRuleCrudService {
   private final CaptureRuleRepository captureRuleRepository;
   private final ConnectionGroupService connectionGroupService;
   private final UserService userService;
   private final UserGroupService userGroupService;
   private final JpaQueryBasedReadRepository<User> userJpaQueryBasedReadRepository;
   private ConnectionService connectionService;

   public CaptureRuleCrudServiceImpl(
      CaptureRuleRepository captureRuleRepository,
      ConnectionGroupService connectionGroupService,
      UserService userService,
      UserGroupService userGroupService,
      JpaQueryBasedReadRepository<User> userJpaQueryBasedReadRepository
   ) {
      super(captureRuleRepository);
      this.captureRuleRepository = captureRuleRepository;
      this.connectionGroupService = connectionGroupService;
      this.userService = userService;
      this.userGroupService = userGroupService;
      this.userJpaQueryBasedReadRepository = userJpaQueryBasedReadRepository;
   }

   @Autowired
   public void setConnectionService(ConnectionService connectionService) {
      this.connectionService = connectionService;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      NativeQuery fetchCaptureRuleQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("c", "c.name", "c.export", "c.keystroke", "c.disabled", "c.expiration_time"))
         .from(CaptureRule.class, "c")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> captureRuleListDtoList = this.nativeQueryBasedReadRepository.findAll(fetchCaptureRuleQuery, tuple -> {
         CaptureRuleListDto captureRuleListDtox = new CaptureRuleListDto();
         captureRuleListDtox.setName((String)tuple.get("name"));
         captureRuleListDtox.setExport((Boolean)tuple.get("export"));
         captureRuleListDtox.setKeystroke((Boolean)tuple.get("keystroke"));
         captureRuleListDtox.setDisabled(Boolean.parseBoolean(tuple.get("disabled").toString()));
         captureRuleListDtox.setExpirationTime(Long.parseLong(tuple.get("expiration_time").toString()));
         AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)captureRuleListDtox);
         return captureRuleListDtox;
      });

      for (ListDto listDto : captureRuleListDtoList) {
         CaptureRuleListDto captureRuleListDto = (CaptureRuleListDto)listDto;
         Object[] counts = this.captureRuleRepository.countConnectionsAndUsersByName(captureRuleListDto.getName()).get(0);
         captureRuleListDto.setNumberOfUsers(Integer.parseInt(String.valueOf(counts[0])) + Integer.parseInt(String.valueOf(counts[1])));
         captureRuleListDto.setNumberOfConnections(Integer.parseInt(String.valueOf(counts[2])) + Integer.parseInt(String.valueOf(counts[3])));
      }

      return Optional.of(captureRuleListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      List<ListDto> captureRuleListDtoList = this.load(filters, sorting).get();
      return Optional.of(PagingUtil.createCustomPage(captureRuleListDtoList, pageable));
   }

   public Optional<DetailsDto> load(String name) {
      CaptureRule captureRule = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchCaptureRuleByNameWithConnectionAssociationQuery(name)))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(CaptureRule.class)));
      List<ConnectionInfoDto> connectionInfoDtoList = new ArrayList<>();

      for (Connection connection : captureRule.getConnections()) {
         ConnectionInfoDto connectionInfoDto = new ConnectionInfoDto();
         connectionInfoDto.setName(connection.getName());
         connectionInfoDto.setType(connection.getType());
         connectionInfoDto.setIpAddress(connection.getIpAddress());
         connectionInfoDto.setPort(connection.getPort());
         connectionInfoDtoList.add(connectionInfoDto);
      }

      List<FilterChain> captureRuleFkFilter = QueryAndFilterUtils.idFilter(captureRule.getId());
      NativeQuery nativeQuery = new NativeQueryBuilder()
         .select("cg.name")
         .from(ConnectionGroup.class, "cg")
         .distinct()
         .joinM2M("tb_capture_rule_connection_group", "crcg", CaptureRule.class, "cr")
         .leftOn("id", "connection_group_id")
         .rightOn("capture_rule_id", "id")
         .joinWhere(captureRuleFkFilter)
         .build();
      List<ConnectionGroupInfoDto> connectionGroupInfoDtoList = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         ConnectionGroupInfoDto connectionGroupInfoDto = new ConnectionGroupInfoDto();
         connectionGroupInfoDto.setName((String)tuple.get(0));
         return connectionGroupInfoDto;
      });
      nativeQuery = new NativeQueryBuilder()
         .select("u.username")
         .from(User.class, "u")
         .distinct()
         .joinM2M("tb_capture_rule_user", "cru", CaptureRule.class, "cr")
         .leftOn("id", "user_id")
         .rightOn("capture_rule_id", "id")
         .joinWhere(captureRuleFkFilter)
         .build();
      List<UserInfoDto> userInfoDtoList = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         UserInfoDto userInfoDto = new UserInfoDto();
         userInfoDto.setUsername((String)tuple.get(0));
         return userInfoDto;
      });
      nativeQuery = new NativeQueryBuilder()
         .select("ug.name")
         .from(UserGroup.class, "ug")
         .distinct()
         .joinM2M("tb_capture_rule_user_group", "crug", CaptureRule.class, "cr")
         .leftOn("id", "user_group_id")
         .rightOn("capture_rule_id", "id")
         .joinWhere(captureRuleFkFilter)
         .build();
      List<UserGroupInfoDto> userGroupInfoDtoList = this.nativeQueryBasedReadRepository.findAll(nativeQuery, tuple -> {
         UserGroupInfoDto userGroupInfoDto = new UserGroupInfoDto();
         userGroupInfoDto.setName((String)tuple.get(0));
         return userGroupInfoDto;
      });
      CaptureRuleDetailsDto captureRuleDetailsDto = new CaptureRuleDetailsDto();
      captureRuleDetailsDto.setName(captureRule.getName());
      captureRuleDetailsDto.setConnections(connectionInfoDtoList);
      captureRuleDetailsDto.setConnectionGroups(connectionGroupInfoDtoList);
      captureRuleDetailsDto.setUsers(userInfoDtoList);
      captureRuleDetailsDto.setUserGroups(userGroupInfoDtoList);
      captureRuleDetailsDto.setDisabled(captureRule.isDisabled());
      captureRuleDetailsDto.setExpirationTime(captureRule.getExpirationTime());
      captureRuleDetailsDto.setExport(captureRule.isExport());
      captureRuleDetailsDto.setKeystroke(captureRule.isKeystroke());
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)captureRule, (AbstractDescriptiveDto)captureRuleDetailsDto);
      return Optional.of(captureRuleDetailsDto);
   }

   public void create(CaptureRuleCreateDto captureRuleCreateDto) throws Exception {
      if (this.existByName(captureRuleCreateDto.getName())) {
         throw new ResourceAlreadyExistsException(new CaptureRuleNameAlreadyExists());
      } else {
         this.checkIfAnyUserAndConnectionIsProvided(captureRuleCreateDto);
         RepositoryContextManager.startNewTransaction();

         try {
            CaptureRule captureRule = new CaptureRule();
            captureRule.setName(captureRuleCreateDto.getName());
            captureRule.setExport(captureRuleCreateDto.isExport());
            captureRule.setKeystroke(captureRuleCreateDto.isKeystroke());
            captureRule.setDisabled(captureRuleCreateDto.isDisabled());
            captureRule.setExpirationTime(captureRuleCreateDto.getExpirationTime());
            this.checkIfAnyUserAndConnectionIsProvided(captureRuleCreateDto);
            if (captureRuleCreateDto.getConnectionGroups() != null) {
               for (String connectionGroupName : captureRuleCreateDto.getConnectionGroups()) {
                  captureRule.addConnectionGroup(this.connectionGroupService.getOneByNameWithAllConnections(connectionGroupName));
               }
            }

            if (captureRuleCreateDto.getConnections() != null) {
               for (String connectionName : captureRuleCreateDto.getConnections()) {
                  Connection connection = this.connectionService.getOne(connectionName);
                  this.validateAssignment(connection, captureRule.getConnectionGroups());
                  captureRule.addConnection(connection);
               }
            }

            if (captureRuleCreateDto.getUserGroups() != null) {
               for (String userGroupName : captureRuleCreateDto.getUserGroups()) {
                  captureRule.addUserGroup((UserGroup)this.userGroupService.getOneByNameWithAllUsers(userGroupName, true));
               }
            }

            if (captureRuleCreateDto.getUsers() != null) {
               for (String userUsername : captureRuleCreateDto.getUsers()) {
                  User user = (User)this.userService.getOne(userUsername);
                  this.validateAssignment(user, captureRule.getUserGroups());
                  captureRule.addUser(user);
               }
            }

            this.validateConnectionUniqueAccessibility(captureRule);
            RepositoryContextManager.commit();
            this.crudRepository.save(captureRule);
         } catch (Exception var6) {
            RepositoryContextManager.rollback();
            throw var6;
         }
      }
   }

   public void update(String name, CaptureRuleUpdateDto captureRuleUpdateDto) throws Exception {
      CaptureRule captureRule = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchCaptureRuleByNameWithConnectionAssociationQuery(name), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(CaptureRule.class)));
      if (!captureRuleUpdateDto.getName().equalsIgnoreCase(captureRule.getName()) && this.existByName(captureRuleUpdateDto.getName())) {
         throw new ResourceAlreadyExistsException(new CaptureRuleNameAlreadyExists());
      } else {
         this.checkIfAnyUserAndConnectionIsProvided(captureRuleUpdateDto);
         RepositoryContextManager.startNewTransaction();

         try {
            captureRule.setName(captureRuleUpdateDto.getName());
            captureRule.setDisabled(captureRuleUpdateDto.isDisabled());
            captureRule.setExpirationTime(captureRuleUpdateDto.getExpirationTime());
            captureRule.setKeystroke(captureRuleUpdateDto.isKeystroke());
            captureRule.setExport(captureRuleUpdateDto.isExport());
            if (captureRuleUpdateDto.getConnectionGroups() != null && !captureRuleUpdateDto.getConnectionGroups().isEmpty()) {
               Set<ConnectionGroup> oldConnectionGroups = captureRule.getConnectionGroups();
               Set<ConnectionGroup> newConnectionGroups = new HashSet<>();

               for (String connectionGroupName : captureRuleUpdateDto.getConnectionGroups()) {
                  newConnectionGroups.add(this.connectionGroupService.getOne(connectionGroupName));
               }

               Set<ConnectionGroup> temp = new HashSet<>();
               temp.addAll(oldConnectionGroups);
               temp.removeAll(newConnectionGroups);

               for (ConnectionGroup connectionGroup : temp) {
                  captureRule.removeConnectionGroup(connectionGroup);
               }

               temp.clear();
               temp.addAll(newConnectionGroups);
               temp.removeAll(oldConnectionGroups);

               for (ConnectionGroup connectionGroup : temp) {
                  captureRule.addConnectionGroup(connectionGroup);
               }
            } else {
               captureRule.getConnectionGroups().clear();
            }

            if (captureRuleUpdateDto.getConnections() != null && !captureRuleUpdateDto.getConnections().isEmpty()) {
               Set<Connection> oldConnections = captureRule.getConnections();
               Set<Connection> newConnections = new HashSet<>();

               for (String connectionName : captureRuleUpdateDto.getConnections()) {
                  newConnections.add(this.connectionService.getOne(connectionName));
               }

               Set<Connection> temp = new HashSet<>();
               temp.addAll(oldConnections);
               temp.removeAll(newConnections);

               for (Connection connection : temp) {
                  captureRule.removeConnection(connection);
               }

               temp.clear();
               temp.addAll(newConnections);
               temp.removeAll(oldConnections);

               for (Connection connection : temp) {
                  captureRule.addConnection(connection);
               }
            } else {
               captureRule.getConnections().clear();
            }

            if (captureRuleUpdateDto.getUserGroups() != null && !captureRuleUpdateDto.getUserGroups().isEmpty()) {
               Set<UserGroup> oldUserGroups = captureRule.getUserGroups();
               Set<UserGroup> newUserGroups = new HashSet<>();

               for (String userGroupName : captureRuleUpdateDto.getUserGroups()) {
                  newUserGroups.add((UserGroup)this.userGroupService.getOne(userGroupName));
               }

               Set<UserGroup> temp = new HashSet<>();
               temp.addAll(oldUserGroups);
               temp.removeAll(newUserGroups);

               for (UserGroup userGroup : temp) {
                  captureRule.removeUserGroup(userGroup);
               }

               temp.clear();
               temp.addAll(newUserGroups);
               temp.removeAll(oldUserGroups);

               for (UserGroup userGroup : temp) {
                  captureRule.addUserGroup(userGroup);
               }
            } else {
               captureRule.getUserGroups().clear();
            }

            if (captureRuleUpdateDto.getUsers() != null && !captureRuleUpdateDto.getUsers().isEmpty()) {
               Set<User> oldUsers = captureRule.getUsers();
               Set<User> newUserGroups = new HashSet<>();

               for (String userGroupName : captureRuleUpdateDto.getUsers()) {
                  newUserGroups.add((User)this.userService.getOne(userGroupName));
               }

               Set<User> temp = new HashSet<>();
               temp.addAll(oldUsers);
               temp.removeAll(newUserGroups);

               for (User user : temp) {
                  captureRule.removeUser(user);
               }

               temp.clear();
               temp.addAll(newUserGroups);
               temp.removeAll(oldUsers);

               for (User user : temp) {
                  captureRule.addUser(user);
               }
            } else {
               captureRule.getUsers().clear();
            }

            this.validateAssignment(captureRule);
            this.validateConnectionUniqueAccessibility(captureRule);
            this.crudRepository.update(captureRule);
            RepositoryContextManager.commit();
         } catch (Exception var9) {
            RepositoryContextManager.rollback();
            throw var9;
         }
      }
   }

   public void delete(String name) throws Exception {
      JpaQuery<CaptureRule> fetchCaptureRuleQuery = new JpaQueryBuilder()
         .from(CaptureRule.class, "cr")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      RepositoryContextManager.startNewTransaction();

      try {
         CaptureRule captureRule = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchCaptureRuleQuery, false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(CaptureRule.class)));
         this.crudRepository.remove(captureRule);
         RepositoryContextManager.commit();
      } catch (ResourceNotFoundException var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   @Override
   public Optional<List<InfoDto>> loadCaptureRulesAssignedToSpecificUser(String username) {
      if (!Optional.ofNullable(this.userService.getOne(username)).isPresent()) {
         throw new ResourceNotFoundException(new EntityNotFoundException(User.class));
      } else {
         List<FilterChain> usernameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("username", username);
         JpaQuery fetchCaptureRulesAssignedToUserQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(User.class, "u")
            .distinct()
            .join("captureRules", "cr")
            .where(usernameFilter)
            .build();
         List<InfoDto> captureRulesAssignedToUser = this.jpaQueryBasedReadRepository
            .findAll(fetchCaptureRulesAssignedToUserQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple));
         fetchCaptureRulesAssignedToUserQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(User.class, "u")
            .distinct()
            .join("userGroups", "ug")
            .join("captureRules", "cr")
            .where(usernameFilter)
            .build();
         captureRulesAssignedToUser.addAll(
            this.jpaQueryBasedReadRepository.findAll(fetchCaptureRulesAssignedToUserQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple))
         );
         return Optional.of(captureRulesAssignedToUser);
      }
   }

   @Override
   public Optional<List<InfoDto>> loadCaptureRulesAssignedToSpecificUserGroup(String userGroupName) {
      if (!Optional.ofNullable(this.userGroupService.getOne(userGroupName)).isPresent()) {
         throw new ResourceNotFoundException(new EntityNotFoundException(UserGroup.class));
      } else {
         JpaQuery fetchCaptureRulesAssignedToUserGroupQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(UserGroup.class, "ug")
            .distinct()
            .join("captureRules", "cr")
            .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroupName))
            .build();
         List<InfoDto> captureRulesAssignedUserGroup = this.jpaQueryBasedReadRepository
            .findAll(fetchCaptureRulesAssignedToUserGroupQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple));
         return Optional.of(captureRulesAssignedUserGroup);
      }
   }

   @Override
   public Optional<List<InfoDto>> loadCaptureRulesSetOverSpecificConnection(String connectionName) {
      if (!Optional.ofNullable(this.connectionService.getOne(connectionName)).isPresent()) {
         throw new ResourceNotFoundException(new EntityNotFoundException(UserGroup.class));
      } else {
         JpaQuery fetchCaptureRulesSetOverSpecificConnectionQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(Connection.class, "c")
            .distinct()
            .join("captureRules", "cr")
            .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", connectionName))
            .build();
         List<InfoDto> captureRulesSetOverConnection = this.jpaQueryBasedReadRepository
            .findAll(fetchCaptureRulesSetOverSpecificConnectionQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple));
         fetchCaptureRulesSetOverSpecificConnectionQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(Connection.class, "c")
            .distinct()
            .join("connectionGroups", "cg")
            .join("captureRules", "cr")
            .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", connectionName))
            .build();
         captureRulesSetOverConnection.addAll(
            this.jpaQueryBasedReadRepository.findAll(fetchCaptureRulesSetOverSpecificConnectionQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple))
         );
         return Optional.of(captureRulesSetOverConnection);
      }
   }

   @Override
   public Optional<List<InfoDto>> loadCaptureRulesSetOverSpecificConnectionGroup(String connectionGroupName) {
      if (!Optional.ofNullable(this.connectionGroupService.getOne(connectionGroupName)).isPresent()) {
         throw new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class));
      } else {
         JpaQuery fetchCaptureRulesSetOverSpecificConnectionGroupQuery = new JpaQueryBuilder()
            .select("cr.name")
            .from(ConnectionGroup.class, "cg")
            .distinct()
            .join("captureRules", "cr")
            .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", connectionGroupName))
            .build();
         List<InfoDto> captureRulesSetOverConnectionGroup = this.jpaQueryBasedReadRepository
            .findAll(fetchCaptureRulesSetOverSpecificConnectionGroupQuery, tuple -> this.convertTupleToCaptureRuleInfoDto(tuple));
         return Optional.of(captureRulesSetOverConnectionGroup);
      }
   }

   private void checkIfAnyUserAndConnectionIsProvided(CaptureRuleCreateDto captureRuleCreateDto) throws NoUserOrUserGroupProvidedException, NoConnectionOrConnectionGroupIsProvidedException {
      if (captureRuleCreateDto.getUsers() != null && !captureRuleCreateDto.getUsers().isEmpty()
         || captureRuleCreateDto.getUserGroups() != null && !captureRuleCreateDto.getUserGroups().isEmpty()) {
         if ((captureRuleCreateDto.getConnections() == null || captureRuleCreateDto.getConnections().isEmpty())
            && (captureRuleCreateDto.getConnectionGroups() == null || captureRuleCreateDto.getConnectionGroups().isEmpty())) {
            throw new NoConnectionOrConnectionGroupIsProvidedException(CaptureRule.class);
         }
      } else {
         throw new NoUserOrUserGroupProvidedException(CaptureRule.class);
      }
   }

   private void validateAssignment(User user, Set<UserGroup> userGroups) throws CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException {
      for (UserGroup userGroup : userGroups) {
         List<User> users = this.userJpaQueryBasedReadRepository
            .findAll(
               new JpaQueryBuilder()
                  .from(User.class, "u")
                  .join("userGroups", "ug")
                  .on(QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroup.getName()))
                  .build()
            );
         if (users.contains(user)) {
            throw new CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException(user.getUsername(), userGroup.getName());
         }
      }
   }

   private void validateAssignment(Connection connection, Set<ConnectionGroup> connectionGroups) throws CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException {
      for (ConnectionGroup connectionGroup : connectionGroups) {
         if (connectionGroup.getConnections().contains(connection)) {
            throw new CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException(connection.getName(), connectionGroup.getName());
         }
      }
   }

   private void validateAssignment(CaptureRule captureRule) throws CaptureRuleIsAlreadyAssignedToUserThroughUserGroupException, CaptureRuleIsAlreadySetOverConnectionThroughConnectionGroupException {
      for (User user : captureRule.getUsers()) {
         this.validateAssignment(user, captureRule.getUserGroups());
      }

      for (Connection connection : captureRule.getConnections()) {
         this.validateAssignment(connection, captureRule.getConnectionGroups());
      }
   }

   private void validateConnectionUniqueAccessibility(CaptureRule captureRule) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException, UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException {
      List<String[]> allConnectionNames = new ArrayList<>();

      for (Connection connection : captureRule.getConnections()) {
         allConnectionNames.add(new String[]{connection.getName()});
      }

      for (ConnectionGroup connectionGroup : captureRule.getConnectionGroups()) {
         for (Connection connection : connectionGroup.getConnections()) {
            allConnectionNames.add(new String[]{connection.getName(), connectionGroup.getName()});
         }
      }

      List<FilterChain> captureRuleNameNotEqualityFilter = new FilterChainBuilder()
         .filter(new FilterBuilder().string("name").neq(captureRule.getName()).ignoreCaseSensitive().buildSingle())
         .build();

      for (User user : captureRule.getUsers()) {
         List<FilterChain> userUsernameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("username", user.getUsername());
         this.validateUserAccess(captureRuleNameNotEqualityFilter, allConnectionNames, userUsernameFilter, user.getUsername(), null);
      }

      for (UserGroup userGroup : captureRule.getUserGroups()) {
         List<FilterChain> userGroupNameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroup.getName());
         String userGroupName = userGroup.getName();
         JpaQuery allIndividualConnectionsOfAllCaptureRulesAssignedToUserGroupQuery = new JpaQueryBuilder()
            .select("cr.name", "c.name")
            .from(UserGroup.class, "ug")
            .distinct()
            .join("captureRules", "cr")
            .on(captureRuleNameNotEqualityFilter)
            .join("connections", "c")
            .where(userGroupNameFilter)
            .build();
         this.validateUserGroupAccess(allIndividualConnectionsOfAllCaptureRulesAssignedToUserGroupQuery, allConnectionNames, userGroupName);
         JpaQuery allGroupedConnectionsOfAllCaptureRulesAssignedToUserGroupQuery = new JpaQueryBuilder()
            .select("cr.name", "c.name")
            .from(UserGroup.class, "ug")
            .distinct()
            .join("captureRules", "cr")
            .on(captureRuleNameNotEqualityFilter)
            .join("connectionGroups", "cg")
            .join("connections", "c")
            .where(userGroupNameFilter)
            .build();
         this.validateUserGroupAccess(allGroupedConnectionsOfAllCaptureRulesAssignedToUserGroupQuery, allConnectionNames, userGroupName);

         for (ir.fidar.core.domain.model.management.User user : this.userJpaQueryBasedReadRepository
            .findAll(
               new JpaQueryBuilder<User>()
                  .from(User.class, "u")
                  .join("userGroups", "ug")
                  .on(QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroupName))
                  .build()
            )) {
            List<FilterChain> userUsernameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("username", user.getUsername());
            this.validateUserAccess(captureRuleNameNotEqualityFilter, allConnectionNames, userUsernameFilter, user.getUsername(), userGroupName);
         }
      }
   }

   private void validateUserAccess(
      List<FilterChain> captureRuleFilter, List<String[]> connectionsToCheckAgainst, List<FilterChain> userFilter, String username, String currentUserGroupName
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      JpaQuery userGroupsOfUserQuery = new JpaQueryBuilder().select("ug.name").from(UserGroup.class, "ug").distinct().join("users", "u").on(userFilter).build();
      List<String> userGroupNames = this.jpaQueryBasedReadRepository.findAll(userGroupsOfUserQuery, tuple -> tuple.get(0).toString());
      List<FilterChain> userUserGroupNameFilter = new FilterChainBuilder().filter(new FilterBuilder().list("name").in(userGroupNames).buildSingle()).build();
      this.validateUserAccessToIndividualConnections(
         captureRuleFilter, connectionsToCheckAgainst, userFilter, userUserGroupNameFilter, username, currentUserGroupName
      );
      this.validateUserAccessToGroupedConnections(
         captureRuleFilter, connectionsToCheckAgainst, userFilter, userUserGroupNameFilter, username, currentUserGroupName
      );
   }

   private void validateUserAccessToIndividualConnections(
      List<FilterChain> captureRuleFilter,
      List<String[]> connectionsToCheckAgainst,
      List<FilterChain> userFilter,
      List<FilterChain> userUserGroupNameFilter,
      String username,
      String currentUserGroupName
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      boolean hasCurrentUserGroup = StringUtils.hasContent(currentUserGroupName);
      JpaQuery allIndividualConnectionsOfAllCaptureRulesAssignedToUserQuery = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(User.class, "u")
         .distinct()
         .join("captureRules", "cr")
         .on(captureRuleFilter)
         .join("connections", "c")
         .where(userFilter)
         .build();
      this.validateUserAccessAsIndividual(
         allIndividualConnectionsOfAllCaptureRulesAssignedToUserQuery, connectionsToCheckAgainst, username, currentUserGroupName, hasCurrentUserGroup
      );
      JpaQuery allIndividualConnectionsOfAllCaptureRulesAssignedToUserThroughGroupsQuery = new JpaQueryBuilder()
         .select("cr.name", "c.name", "ug.name")
         .from(UserGroup.class, "ug")
         .distinct()
         .join("captureRules", "cr")
         .on(captureRuleFilter)
         .join("connections", "c")
         .where(userUserGroupNameFilter)
         .build();
      this.validateUserAccessAsGrouped(
         allIndividualConnectionsOfAllCaptureRulesAssignedToUserThroughGroupsQuery,
         connectionsToCheckAgainst,
         username,
         currentUserGroupName,
         hasCurrentUserGroup
      );
   }

   private void validateUserAccessToGroupedConnections(
           List<FilterChain> captureRuleFilter,
           List<String[]> connectionsToCheckAgainst,
           List<FilterChain> userFilter,
           List<FilterChain> userUserGroupNameFilter,
           String username,
           String currentUserGroupName
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      boolean hasCurrentUserGroup = StringUtils.hasContent(currentUserGroupName);

      // Validate grouped connections of capture rules assigned to the user
      validateConnections(
              new JpaQueryBuilder()
                      .select("cr.name", "c.name")
                      .from(User.class, "u")
                      .distinct()
                      .join("captureRules", "cr")
                      .on(captureRuleFilter)
                      .join("connectionGroups", "cg")
                      .join("connections", "c")
                      .where(userFilter)
                      .build(),
              connectionsToCheckAgainst,
              hasCurrentUserGroup,
              username,
              currentUserGroupName,
              false
      );

      // Validate individual connections assigned to the user through groups
      validateConnections(
              new JpaQueryBuilder()
                      .select("cr.name", "c.name", "ug.name")
                      .from(UserGroup.class, "ug")
                      .distinct()
                      .join("captureRules", "cr")
                      .on(captureRuleFilter)
                      .join("connectionGroups", "cg")
                      .join("connections", "c")
                      .where(userUserGroupNameFilter)
                      .build(),
              connectionsToCheckAgainst,
              hasCurrentUserGroup,
              username,
              currentUserGroupName,
              true
      );
   }

   private void validateConnections(
           JpaQuery query,
           List<String[]> connectionsToCheckAgainst,
           boolean hasCurrentUserGroup,
           String username,
           String currentUserGroupName,
           boolean throughUserGroup
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      List<String[]> results = this.jpaQueryBasedReadRepository.findAll(query, tuple -> {
         if (throughUserGroup) {
            return new String[]{(String) tuple.get(0), (String) tuple.get(1), (String) tuple.get(2)};
         } else {
            return new String[]{(String) tuple.get(0), (String) tuple.get(1)};
         }
      });

      for (String[] result : results) {
         for (String[] connection : connectionsToCheckAgainst) {
            if (result[1].equalsIgnoreCase(connection[0])) {
               handleException(
                       result,
                       connection,
                       hasCurrentUserGroup,
                       username,
                       currentUserGroupName,
                       throughUserGroup
               );
            }
         }
      }
   }

   private void handleException(
           String[] result,
           String[] connection,
           boolean hasCurrentUserGroup,
           String username,
           String currentUserGroupName,
           boolean throughUserGroup
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      if (connection.length == 2) {
         if (throughUserGroup) {
            throw hasCurrentUserGroup
                    ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
                    username, result[0], result[1], connection[1], result[2], currentUserGroupName
            )
                    : new UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
                    username, result[0], result[1], connection[1], result[2]
            );
         } else {
            throw hasCurrentUserGroup
                    ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
                    username, result[0], result[1], connection[1], currentUserGroupName
            )
                    : new UserAlreadyAccessConnectionByAnotherCaptureRuleException(
                    username, result[0], result[1], connection[1]
            );
         }
      }

      if (throughUserGroup) {
         throw hasCurrentUserGroup
                 ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
                 username, result[0], result[1], result[2], currentUserGroupName
         )
                 : new UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
                 username, result[0], result[1], result[2]
         );
      } else {
         throw hasCurrentUserGroup
                 ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
                 username, result[0], result[1], currentUserGroupName
         )
                 : new UserAlreadyAccessConnectionByAnotherCaptureRuleException(
                 username, result[0], result[1]
         );
      }
   }


   private void validateUserAccessAsIndividual(
           JpaQuery query,
           List<String[]> connectionsToCheckAgainst,
           String username,
           String currentUserGroupName,
           boolean isUserInAGroup
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      List<String[]> results = this.jpaQueryBasedReadRepository.findAll(query, tuple ->
              new String[]{(String) tuple.get(0), (String) tuple.get(1)});

      for (String[] result : results) {
         for (String[] connection : connectionsToCheckAgainst) {
            if (result[1].equalsIgnoreCase(connection[0])) {
               handleIndividualException(result, connection, isUserInAGroup, username, currentUserGroupName);
            }
         }
      }
   }

   private void handleIndividualException(
           String[] result,
           String[] connection,
           boolean isUserInAGroup,
           String username,
           String currentUserGroupName
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      if (connection.length == 2) {
         throw isUserInAGroup
                 ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
                 username, result[0], result[1], connection[1], currentUserGroupName
         )
                 : new UserAlreadyAccessConnectionByAnotherCaptureRuleException(
                 username, result[0], result[1], connection[1]
         );
      }

      throw isUserInAGroup
              ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleException(
              username, result[0], result[1], currentUserGroupName
      )
              : new UserAlreadyAccessConnectionByAnotherCaptureRuleException(
              username, result[0], result[1]
      );
   }


   private void validateUserAccessAsGrouped(
           JpaQuery query,
           List<String[]> connectionsToCheckAgainst,
           String username,
           String currentUserGroupName,
           boolean isUserInAGroup
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      List<String[]> results = this.jpaQueryBasedReadRepository.findAll(query, tuple ->
              new String[]{(String) tuple.get(0), (String) tuple.get(1), (String) tuple.get(2)});

      for (String[] result : results) {
         for (String[] connection : connectionsToCheckAgainst) {
            if (result[1].equalsIgnoreCase(connection[0])) {
               handleGroupedException(result, connection, isUserInAGroup, username, currentUserGroupName);
            }
         }
      }
   }

   private void handleGroupedException(
           String[] result,
           String[] connection,
           boolean isUserInAGroup,
           String username,
           String currentUserGroupName
   ) throws UserAlreadyAccessConnectionByAnotherCaptureRuleException {
      if (connection.length == 2) {
         throw isUserInAGroup
                 ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
                 username, result[0], result[1], connection[1], result[2], currentUserGroupName
         )
                 : new UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
                 username, result[0], result[1], connection[1], result[2]
         );
      }

      throw isUserInAGroup
              ? new UserGroupUserAlreadyAccessConnectionByAnotherCaptureRuleThroughAnotherUserGroupException(
              username, result[0], result[1], result[2], currentUserGroupName
      )
              : new UserAlreadyAccessConnectionByAnotherCaptureRuleThroughUserGroupException(
              username, result[0], result[1], result[2]
      );
   }


   private void validateUserGroupAccess(
           JpaQuery query,
           List<String[]> connectionToCheckAgainst,
           String userGroupName
   ) throws UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException {
      List<String[]> results = this.jpaQueryBasedReadRepository.findAll(query, tuple ->
              new String[]{(String) tuple.get(0), (String) tuple.get(1)});

      for (String[] result : results) {
         for (String[] connection : connectionToCheckAgainst) {
            if (result[1].equalsIgnoreCase(connection[0])) {
               handleUserGroupException(result, connection, userGroupName);
            }
         }
      }
   }

   private void handleUserGroupException(
           String[] result,
           String[] connection,
           String userGroupName
   ) throws UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException {
      if (connection.length == 2) {
         throw new UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException(
                 userGroupName, result[0], result[1], connection[1]
         );
      }

      throw new UserGroupAlreadyAccessConnectionByAnotherCaptureRuleException(
              userGroupName, result[0], result[1]
      );
   }

   private List<String[]> fetchCaptureRulesWithTheirConnections(JpaQuery query) {
      return this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{tuple.get(0).toString(), tuple.get(1).toString()});
   }

   private boolean existByName(String name) {
      return this.nativeQueryBasedReadRepository.exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(CaptureRule.class, "name", name));
   }

   private JpaQuery<CaptureRule> fetchCaptureRuleByNameWithConnectionAssociationQuery(String name) {
      return new JpaQueryBuilder()
         .from(CaptureRule.class, "cr")
         .distinct()
         .leftJoin("connections", "c")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
   }

   private CaptureRuleInfoDto convertTupleToCaptureRuleInfoDto(Tuple tuple) {
      CaptureRuleInfoDto captureRuleInfoDto = new CaptureRuleInfoDto();
      captureRuleInfoDto.setName(tuple.get(0).toString());
      return captureRuleInfoDto;
   }
}
