package ir.fidar.pam.da.repository;

import ir.fidar.pam.domain.model.SymmetricKey;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SymmetricKeyRepository extends JpaRepository<SymmetricKey, Long> {
}
