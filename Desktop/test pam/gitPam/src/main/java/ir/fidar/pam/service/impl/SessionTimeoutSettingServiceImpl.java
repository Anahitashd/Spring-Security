package ir.fidar.pam.service.impl;

import ir.fidar.core.service.impl.generic.SingletonEntityGenericServiceImpl;
import ir.fidar.pam.da.repository.SessionTimeoutSettingRepository;
import ir.fidar.pam.domain.model.SessionTimeoutSetting;
import ir.fidar.pam.service.SessionTimeoutSettingService;
import org.springframework.stereotype.Service;

@Service
public class SessionTimeoutSettingServiceImpl extends SingletonEntityGenericServiceImpl<SessionTimeoutSetting> implements SessionTimeoutSettingService {
   private final SessionTimeoutSettingRepository sessionTimeoutSettingRepository;

   public SessionTimeoutSettingServiceImpl(SessionTimeoutSettingRepository sessionTimeoutSettingRepository) {
      super(sessionTimeoutSettingRepository);
      this.sessionTimeoutSettingRepository = sessionTimeoutSettingRepository;
   }
}
