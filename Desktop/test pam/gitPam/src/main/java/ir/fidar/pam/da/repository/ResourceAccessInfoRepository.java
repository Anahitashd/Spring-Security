package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.ResourceAccessInfo;
import org.springframework.stereotype.Repository;

@Repository
public interface ResourceAccessInfoRepository extends GenericRepository<ResourceAccessInfo, Long> {
}
