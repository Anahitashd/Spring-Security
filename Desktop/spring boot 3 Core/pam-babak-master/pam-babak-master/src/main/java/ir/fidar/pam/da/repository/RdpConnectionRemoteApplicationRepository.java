package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.connection.RdpConnectionRemoteApplication;
import java.util.List;
import org.springframework.stereotype.Repository;

@Repository
public interface RdpConnectionRemoteApplicationRepository extends GenericRepository<RdpConnectionRemoteApplication, Long> {
   RdpConnectionRemoteApplication findOneByNameAndConnectionId(String var1, Long var2);

   List<RdpConnectionRemoteApplication> findAllByConnectionId(Long var1);
}
