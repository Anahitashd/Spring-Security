package ir.fidar.pam.da.repository;

import ir.fidar.pam.domain.model.ocr.SessionCapturedImageText;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionCapturedImageTextRepository extends JpaRepository<SessionCapturedImageText, Long> {
   List<SessionCapturedImageText> findAllBySessionId(String var1);
}
