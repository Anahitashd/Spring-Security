package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.session.TransparentCapture;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TransparentCaptureRepository extends GenericRepository<TransparentCapture, Long> {
   TransparentCapture findOneBySessionId(String var1);

   default boolean existsByUuidGlobally(String sessionId) {
      Number result = this.exists(sessionId);
      return result != null && result.intValue() == 1;
   }

   boolean existsBySessionId(String var1);

   @Query(
      value = "SELECT EXISTS(SELECT c.session_id FROM tb_capture c WHERE c.session_id = :sessionId) OR EXISTS(SELECT tc.session_id FROM tb_transparent_capture tc WHERE tc.session_id = :sessionId)",
      nativeQuery = true
   )
   Number exists(@Param("sessionId") String var1);
}
