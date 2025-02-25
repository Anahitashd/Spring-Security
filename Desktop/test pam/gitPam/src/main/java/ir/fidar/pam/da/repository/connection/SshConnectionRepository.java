package ir.fidar.pam.da.repository.connection;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.connection.SshConnection;
import org.springframework.stereotype.Repository;

@Repository
public interface SshConnectionRepository extends GenericRepository<SshConnection, Long> {
}
