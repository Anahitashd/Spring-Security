package ir.fidar.pam.service.impl.connection;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.connection.ConnectionGroupRepository;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupCreateDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupDetailsDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupListDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupUpdateDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.exception.ConnectionGroupNameAlreadyInUseException;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.connection.ConnectionGroupCrudService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ConnectionGroupCrudServiceImpl extends GlobalCommonServiceImpl<ConnectionGroup> implements ConnectionGroupCrudService {
   private final ConnectionService connectionService;
   private final JpaQueryBasedReadRepository<CaptureRule> captureRuleJpaQueryBasedReadRepository;
   private final GenericCrudRepository<CaptureRule> captureRuleCrudRepository;
   private final AccessRuleService accessRuleService;

   public ConnectionGroupCrudServiceImpl(
      ConnectionGroupRepository connectionGroupRepository,
      ConnectionService connectionService,
      JpaQueryBasedReadRepository<CaptureRule> captureRuleJpaQueryBasedReadRepository,
      GenericCrudRepository<CaptureRule> captureRuleCrudRepository,
      @Lazy AccessRuleService accessRuleService
   ) {
      super(connectionGroupRepository);
      this.connectionService = connectionService;
      this.captureRuleJpaQueryBasedReadRepository = captureRuleJpaQueryBasedReadRepository;
      this.captureRuleCrudRepository = captureRuleCrudRepository;
      this.accessRuleService = accessRuleService;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      JpaQuery<ConnectionGroup> userGroupJpaQuery = new JpaQueryBuilder()
         .from(ConnectionGroup.class)
         .distinct()
         .leftJoin("connections")
         .fetch()
         .orderBy(sorting)
         .build();
      List<ConnectionGroup> connectionGroups = this.jpaQueryBasedReadRepository.findAll(userGroupJpaQuery);
      List<ListDto> connectionGroupListDtoList = new ArrayList<>();

      for (ConnectionGroup connectionGroup : connectionGroups) {
         ConnectionGroupListDto connectionGroupListDto = new ConnectionGroupListDto();
         connectionGroupListDto.setName(connectionGroup.getName());
         connectionGroupListDto.setNumberOfConnections(connectionGroup.getConnections().size());
         AuditionInfoAndGlobalFieldsCopier.copy(connectionGroup, connectionGroupListDto);
         connectionGroupListDtoList.add(connectionGroupListDto);
      }

      return Optional.of(connectionGroupListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      List<ListDto> connectionGroupListDtoList = this.load(filters, sorting).get();
      CustomPageDto<ListDto> pageDto = PagingUtil.createCustomPage(connectionGroupListDtoList, pageable);
      return Optional.of(pageDto);
   }

   public Optional<DetailsDto> load(String name) {
      ConnectionGroup connectionGroup = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionGroupWillAllAssociatedConnections(name))
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
      List<ConnectionInfoDto> connectionInfoDtoList = new ArrayList<>();

      for (Connection connection : connectionGroup.getConnections()) {
         ConnectionInfoDto connectionInfoDto = new ConnectionInfoDto();
         connectionInfoDto.setIpAddress(connection.getIpAddress());
         connectionInfoDto.setName(connection.getName());
         connectionInfoDto.setType(connection.getType());
         connectionInfoDto.setPort(connection.getPort());
         connectionInfoDtoList.add(connectionInfoDto);
      }

      ConnectionGroupDetailsDto connectionGroupDetailsDto = new ConnectionGroupDetailsDto();
      connectionGroupDetailsDto.setName(connectionGroup.getName());
      connectionGroupDetailsDto.setConnections(connectionInfoDtoList);
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)connectionGroup, (AbstractDescriptiveDto)connectionGroupDetailsDto);
      return Optional.of(connectionGroupDetailsDto);
   }

   public void create(ConnectionGroupCreateDto connectionGroupCreateDto) throws Exception {
      if (this.existsByName(connectionGroupCreateDto.getName())) {
         throw new ResourceAlreadyExistsException(new ConnectionGroupNameAlreadyInUseException());
      } else {
         ConnectionGroup connectionGroup = new ConnectionGroup();
         connectionGroup.setName(connectionGroupCreateDto.getName());
         connectionGroup.setDescription(connectionGroupCreateDto.getDescription());

         for (String connectionName : connectionGroupCreateDto.getConnections()) {
            Connection connection = this.connectionService.getOne(connectionName);
            connectionGroup.addConnection(connection);
         }

         this.crudRepository.save(connectionGroup);
      }
   }

   public void update(String name, ConnectionGroupUpdateDto connectionGroupUpdateDto) throws Exception {
      ConnectionGroup connectionGroup = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionGroupWillAllAssociatedConnections(name), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
      if (!connectionGroupUpdateDto.getName().equalsIgnoreCase(connectionGroup.getName()) && this.existsByName(connectionGroupUpdateDto.getName())) {
         throw new ResourceAlreadyExistsException(new ConnectionGroupNameAlreadyInUseException());
      } else {
         RepositoryContextManager.startNewTransaction();

         try {
            connectionGroup.setName(connectionGroupUpdateDto.getName());
            connectionGroup.setDescription(connectionGroupUpdateDto.getDescription());
            if (connectionGroupUpdateDto.getConnections() != null && !connectionGroupUpdateDto.getConnections().isEmpty()) {
               Set<Connection> oldConnections = connectionGroup.getConnections();
               Set<Connection> newConnections = new HashSet<>();

               for (String connectionName : connectionGroupUpdateDto.getConnections()) {
                  newConnections.add(this.connectionService.getOne(connectionName));
               }

               Set<Connection> temp = new HashSet<>(oldConnections);
               temp.removeAll(newConnections);

               for (Connection connection : temp) {
                  connectionGroup.removeConnection(connection);
               }

               temp.clear();
               temp.addAll(newConnections);
               temp.removeAll(oldConnections);

               for (Connection connection : temp) {
                  connectionGroup.addConnection(connection);
               }
            } else {
               connectionGroup.getConnections().clear();
            }

            this.accessRuleService.validateConnectionGroupConnectionMembership(connectionGroup);
            this.crudRepository.update(connectionGroup);
            RepositoryContextManager.commit();
         } catch (Exception var9) {
            RepositoryContextManager.rollback();
            throw var9;
         }
      }
   }

   public void delete(String name) throws Exception {
      JpaQuery<ConnectionGroup> fetchConnectionGroupQuery = new JpaQueryBuilder()
         .from(ConnectionGroup.class, "cg")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
      RepositoryContextManager.startNewTransaction();

      try {
         ConnectionGroup connectionGroup = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchConnectionGroupQuery, false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
         this.checkAssignedCaptureRulesAndRemoveIfRequired(connectionGroup);
         this.crudRepository.remove(connectionGroup);
         RepositoryContextManager.commit();
      } catch (Exception var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   private void checkAssignedCaptureRulesAndRemoveIfRequired(ConnectionGroup connectionGroup) {
      JpaQuery<CaptureRule> fetchCaptureRulesSetOverConnectionGroupQuery = new JpaQueryBuilder()
         .from(CaptureRule.class, "cr")
         .distinct()
         .join("connectionGroups", "cg")
         .fetch()
         .build();

      for (CaptureRule captureRule : this.captureRuleJpaQueryBasedReadRepository.findAll(fetchCaptureRulesSetOverConnectionGroupQuery, false)) {
         captureRule.removeConnectionGroup(connectionGroup);
         if (captureRule.getConnectionGroups().isEmpty()) {
            NativeQuery checkIfCaptureRuleHasAnyConnection = new NativeQueryBuilder()
               .checkExistence()
               .from(Connection.class, "c")
               .joinM2M("tb_capture_rule_connection", "arc", CaptureRule.class, "cr")
               .leftOn("id", "connection_id")
               .rightOn("capture_rule_id", "id")
               .joinWhere(QueryAndFilterUtils.idFilter(captureRule.getId()))
               .build();
            if (!this.nativeQueryBasedReadRepository.exists(checkIfCaptureRuleHasAnyConnection)) {
               this.captureRuleCrudRepository.remove(captureRule);
            }
         }
      }
   }

   protected JpaQuery<ConnectionGroup> fetchConnectionGroupWillAllAssociatedConnections(String name) {
      return new JpaQueryBuilder()
         .from(ConnectionGroup.class, "cg")
         .leftJoin("connections", "c")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name))
         .build();
   }

   private boolean existsByName(String name) {
      return this.nativeQueryBasedReadRepository
         .exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(ConnectionGroup.class, "name", name));
   }
}
