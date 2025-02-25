package ir.fidar.pam.da.repository.connection;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.connection.VncConnection;
import org.springframework.stereotype.Repository;

@Repository
public interface VncConnectionRepository extends GenericRepository<VncConnection, Long> {
}
