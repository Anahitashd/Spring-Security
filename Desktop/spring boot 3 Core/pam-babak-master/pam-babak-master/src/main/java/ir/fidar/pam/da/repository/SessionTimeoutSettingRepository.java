package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.SingletonEntityGenericRepository;
import ir.fidar.pam.domain.model.SessionTimeoutSetting;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionTimeoutSettingRepository extends SingletonEntityGenericRepository<SessionTimeoutSetting> {
}
