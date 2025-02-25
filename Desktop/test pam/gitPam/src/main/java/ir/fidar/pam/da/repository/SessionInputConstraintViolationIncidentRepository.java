package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import java.util.List;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionInputConstraintViolationIncidentRepository extends GenericRepository<SessionInputConstraintViolationIncident, Long> {
   List<SessionInputConstraintViolationIncident> findAllByCaptureId(Long var1);
}
