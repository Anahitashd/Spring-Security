package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.session.SessionScanningTransferredFile;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionScanningTransferredFileRepository extends GenericRepository<SessionScanningTransferredFile, Long> {
   SessionScanningTransferredFile findOneByUuid(String var1);

   boolean existsByUuid(String var1);
}
