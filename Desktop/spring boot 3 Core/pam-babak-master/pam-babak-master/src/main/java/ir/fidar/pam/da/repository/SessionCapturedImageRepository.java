package ir.fidar.pam.da.repository;

import ir.fidar.pam.domain.model.ocr.SessionCapturedImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionCapturedImageRepository extends JpaRepository<SessionCapturedImage, Long> {
}
