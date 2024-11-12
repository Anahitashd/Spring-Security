package ir.fidar.pam.service.impl.connection;

import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.pam.da.repository.connection.ConnectionGroupRepository;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.connection.ConnectionGroupService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

@Service
public class ConnectionGroupServiceImpl extends ConnectionGroupCrudServiceImpl implements ConnectionGroupService {
   private final ConnectionGroupRepository connectionGroupRepository;

   public ConnectionGroupServiceImpl(
      ConnectionGroupRepository connectionGroupRepository,
      ConnectionService connectionService,
      JpaQueryBasedReadRepository<CaptureRule> captureRuleJpaQueryBasedReadRepository,
      GenericCrudRepository<CaptureRule> captureRuleCrudRepository,
      @Lazy AccessRuleService accessRuleService
   ) {
      super(connectionGroupRepository, connectionService, captureRuleJpaQueryBasedReadRepository, captureRuleCrudRepository, accessRuleService);
      this.connectionGroupRepository = connectionGroupRepository;
   }

   @Override
   public List<ConnectionGroup> getAll() {
      return this.connectionGroupRepository.findAll();
   }

   public ConnectionGroup getOne(String name) {
      return Optional.of(this.connectionGroupRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
   }

   public ConnectionGroup getOne(Long id) {
      return Optional.of(this.connectionGroupRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
   }

   @Override
   public ConnectionGroup getOneByNameWithAllConnections(String name) {
      return Optional.of(this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionGroupWillAllAssociatedConnections(name)))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionGroup.class)));
   }

   @Override
   public ConnectionGroupInfoDto convertToInfoDto(ConnectionGroup connectionGroup) {
      if (connectionGroup == null) {
         return null;
      } else {
         ConnectionGroupInfoDto connectionGroupInfoDto = new ConnectionGroupInfoDto();
         connectionGroupInfoDto.setName(connectionGroup.getName());
         return connectionGroupInfoDto;
      }
   }

   @Override
   public Set<ConnectionGroupInfoDto> convertToInfoDto(Collection<ConnectionGroup> connectionGroups) {
      return connectionGroups == null ? null : connectionGroups.stream().map(this::convertToInfoDto).collect(Collectors.toSet());
   }
}
