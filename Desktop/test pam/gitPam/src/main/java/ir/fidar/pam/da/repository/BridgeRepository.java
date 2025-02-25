package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.Bridge;
import org.springframework.stereotype.Repository;

@Repository
public interface BridgeRepository extends GenericRepository<Bridge, Long> {
   Bridge findOneByNameIgnoreCase(String var1);
}
