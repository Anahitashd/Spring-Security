package ir.fidar.pam.da.repository;

import ir.fidar.core.da.repository.AbstractUserRepository;
import ir.fidar.pam.domain.model.management.User;
import java.util.Set;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
@Primary
public interface UserRepository extends AbstractUserRepository<User> {
   @Query(
      value = "SELECT u.* FROM tb_user u JOIN tb_access_rule_user aru ON u.id = aru.user_id WHERE aru.access_rule_id = :ar_id UNION ALL SELECT u.* FROM tb_user u     JOIN tb_user_user_group uug ON u.id = uug.user_id     JOIN tb_access_rule_user_group arug ON uug.user_group_id = arug.user_group_id WHERE arug.access_rule_id = :ar_id",
      nativeQuery = true
   )
   Set<User> findAllByAccessRuleId(@Param("ar_id") long var1);
}
