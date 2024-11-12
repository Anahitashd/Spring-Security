package ir.fidar.pam.da.repository;

import ir.fidar.core.da.repository.AbstractUserGroupRepository;
import ir.fidar.pam.domain.model.management.UserGroup;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Repository;

@Repository
@Primary
public interface UserGroupRepository extends AbstractUserGroupRepository<UserGroup> {
}
