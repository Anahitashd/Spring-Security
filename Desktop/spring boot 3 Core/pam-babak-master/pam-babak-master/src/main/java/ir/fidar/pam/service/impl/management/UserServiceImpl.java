package ir.fidar.pam.service.impl.management;

import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.domain.model.management.MessageHistory;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.security.sessionmanagement.SessionInfo;
import ir.fidar.core.security.sessionmanagement.SessionService;
import ir.fidar.core.service.impl.management.user.AbstractUserServiceImpl;
import ir.fidar.core.service.management.security.PasswordComplexitySettingService;
import ir.fidar.core.service.management.security.RoleService;
import ir.fidar.core.service.management.user.UserPropertyActivationDeactivationService;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.pam.da.repository.UserRepository;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.service.UserService;
import java.util.Optional;
import java.util.Set;
import jakarta.validation.Validator;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Primary
public class UserServiceImpl extends AbstractUserServiceImpl<User> implements UserService {
   private final UserRepository userRepository;

   public UserServiceImpl(
      UserRepository userRepository,
      RoleService roleService,
      PasswordEncoder passwordEncoder,
      SessionService<? extends SessionInfo> sessionService,
      UserPropertyActivationDeactivationService userPropertyActivationDeactivationService,
      Validator validator,
      PasswordComplexitySettingService passwordComplexitySettingService,
      GenericCrudRepository<MessageHistory> messageHistoryCrudRepository,
      SmsSender smsSender,
      EmailSender emailSender
   ) {
      super(
         userRepository,
         roleService,
         passwordEncoder,
         sessionService,
         userPropertyActivationDeactivationService,
         validator,
         passwordComplexitySettingService,
         messageHistoryCrudRepository,
         smsSender,
         emailSender
      );
      this.userRepository = userRepository;
   }

   @Override
   public Class<User> getPersistingInstanceClass() {
      return User.class;
   }

   @Override
   public User getOneById(Long id, boolean readOnly) {
      JpaQuery<User> fetchUserByIdQuery = new JpaQueryBuilder().from(User.class, "u").where(QueryAndFilterUtils.idFilter(id)).build();
      return (User) Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchUserByIdQuery, readOnly))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(User.class)));
   }

   @Override
   public void save(User user) {
      this.crudRepository.save(user);
   }

   @Override
   public Set<User> getAllByAccessRuleId(long accessRuleId) {
      return this.userRepository.findAllByAccessRuleId(accessRuleId);
   }
}
