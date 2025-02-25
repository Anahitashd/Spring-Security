package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnectionId;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessRuleConnectionRepository extends GenericRepository<AccessRuleConnection, AccessRuleConnectionId> {
}
