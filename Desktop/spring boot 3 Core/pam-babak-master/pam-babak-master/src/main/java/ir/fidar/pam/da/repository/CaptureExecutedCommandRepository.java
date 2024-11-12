package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

@Repository
public interface CaptureExecutedCommandRepository extends GenericRepository<CaptureExecutedCommand, Long> {
   Page<CaptureExecutedCommand> findAllByCaptureId(Long var1, Pageable var2);
}
