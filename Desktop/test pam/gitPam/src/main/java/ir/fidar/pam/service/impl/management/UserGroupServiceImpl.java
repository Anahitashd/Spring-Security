package ir.fidar.pam.service.impl.management;

import ir.fidar.core.service.impl.management.user.AbstractUserGroupServiceImpl;
import ir.fidar.pam.da.repository.UserGroupRepository;
import ir.fidar.pam.domain.model.management.UserGroup;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

@Service
@Primary
public class UserGroupServiceImpl extends AbstractUserGroupServiceImpl<UserGroup> {
   public UserGroupServiceImpl(UserGroupRepository userGroupRepository) {
      super(userGroupRepository);
   }

   @Override
   public Class<UserGroup> getPersistingInstanceClass() {
      return UserGroup.class;
   }
}
