package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.repository.JpaQueryBasedReadRepository;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.service.management.user.UserGroupService;
import ir.fidar.core.service.management.user.UserService;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.da.repository.CaptureRuleRepository;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.service.connection.ConnectionGroupService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CaptureRuleService extends CaptureRuleCrudServiceImpl implements ir.fidar.pam.service.CaptureRuleService {
   private final CaptureRuleRepository captureRuleRepository;
   private ConnectionService connectionService;

   public CaptureRuleService(
      CaptureRuleRepository captureRuleRepository,
      ConnectionGroupService connectionGroupService,
      UserService userService,
      UserGroupService userGroupService,
      JpaQueryBasedReadRepository<User> userJpaQueryBasedReadRepository
   ) {
      super(captureRuleRepository, connectionGroupService, userService, userGroupService, userJpaQueryBasedReadRepository);
      this.captureRuleRepository = captureRuleRepository;
   }

   @Autowired
   @Override
   public void setConnectionService(ConnectionService connectionService) {
      super.setConnectionService(connectionService);
      this.connectionService = connectionService;
   }

   @Override
   public List<CaptureRule> getAll() {
      return this.captureRuleRepository.findAll();
   }

   public CaptureRule getOne(String name) {
      return Optional.ofNullable(this.captureRuleRepository.findOneByName(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(CaptureRule.class)));
   }

   public CaptureRule getOne(Long id) {
      return Optional.ofNullable(this.captureRuleRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(CaptureRule.class)));
   }

   @Override
   public void delete(Long id) {
      this.crudRepository.remove(CaptureRule.class, QueryAndFilterUtils.idFilter(id));
   }

   @Override
   public ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus checkUserAccessibilityOverConnection(String connectionName) throws NoCaptureRuleIsFoundForConnectionException {
      Connection connection = this.connectionService.getOne(connectionName);
      CaptureRule captureRule = this.captureRuleRepository
         .findOneByUserIdAndConnectionId(super.authorizationService.getCurrentUserInfo().getId(), connection.getId());
      if (captureRule == null) {
         return ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_PRIVILEGED;
      } else if (!captureRule.isExport()) {
         return ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_EXPORTABLE;
      } else if (captureRule.isDisabled()) {
         return ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.DISABLED;
      } else {
         long expirationTime = captureRule.getExpirationTime();
         return expirationTime != 0L && expirationTime <= Instant.now().getEpochSecond()
            ? ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.EXPIRED
            : ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.ACCESSIBLE;
      }
   }

   @Override
   public CaptureRule getCaptureRuleOfUserOverConnection(Long userId, Long connectionId) {
      return this.captureRuleRepository.findOneByUserIdAndConnectionId(userId, connectionId, Instant.now().getEpochSecond());
   }
}
