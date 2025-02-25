package ir.fidar.pam.service;

import ir.fidar.pam.domain.model.management.User;
import java.util.Set;

public interface UserService extends ir.fidar.core.service.management.user.UserService<User> {
   User getOneById(Long var1, boolean var2);

   void save(User var1);

   Set<User> getAllByAccessRuleId(long var1);
}
