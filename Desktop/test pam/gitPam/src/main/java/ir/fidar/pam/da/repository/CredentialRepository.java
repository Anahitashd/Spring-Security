package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.model.credential.DomainCredential;
import ir.fidar.pam.domain.model.credential.PrivateKeyCredential;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import java.util.List;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialRepository extends GenericRepository<Credential, Long> {
   List<Credential> findAllByConnectionId(Long var1);

   Credential findOneByLabelAndConnectionId(String var1, Long var2);

   @Query("SELECT c FROM AccessRuleConnection arc JOIN arc.credential c WHERE arc.connection.id = :con_id AND arc.accessRule.id = :ar_id")
   Credential findOneByAccessRuleAndConnection(@Param("ar_id") long var1, @Param("con_id") long var3);

   @Query("SELECT c FROM UsernamePasswordCredential c WHERE c.id = :id")
   UsernamePasswordCredential findUsernamePasswordCredentialById(@Param("id") long var1);

   @Query("SELECT c FROM DomainCredential c WHERE c.id = :id")
   DomainCredential findDomainCredentialById(@Param("id") long var1);

   @Query("SELECT c FROM PrivateKeyCredential c WHERE c.id = :id")
   PrivateKeyCredential findPrivateKeyCredentialById(@Param("id") long var1);
}
