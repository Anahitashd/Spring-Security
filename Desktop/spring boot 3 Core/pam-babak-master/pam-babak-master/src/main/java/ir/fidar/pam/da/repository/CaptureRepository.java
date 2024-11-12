package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.type.CaptureStatus;
import java.util.Set;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public interface CaptureRepository extends GenericRepository<Capture, Long> {
   Capture findOneBySessionId(String var1);

   @Modifying
   @Transactional
   @Query("UPDATE Capture c SET c.status = 2 WHERE c.status = 1")
   void closeAllOpenCaptures();

   @Modifying
   @Transactional
   @Query("UPDATE Capture c SET c.status = 2 WHERE c.status = 1 AND c.sessionId NOT IN (:liveSessionIds)")
   void syncCaptureAndSessionStatus(@Param("liveSessionIds") Set<String> var1);

   boolean existsBySessionId(String var1);

   boolean existsByConnectionNameIgnoreCase(String var1);

   long countDistinctByStatus(CaptureStatus var1);

   default long countLiveCaptures() {
      return this.countDistinctByStatus(CaptureStatus.LIVE);
   }
}
