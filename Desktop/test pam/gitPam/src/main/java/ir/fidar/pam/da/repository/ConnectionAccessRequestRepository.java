package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.ConnectionAccessRequest;
import org.springframework.stereotype.Repository;

@Repository
public interface ConnectionAccessRequestRepository extends GenericRepository<ConnectionAccessRequest, Long> {
   ConnectionAccessRequest findOneByIdentifier(String var1);

   boolean existsByIdentifier(String var1);
}
