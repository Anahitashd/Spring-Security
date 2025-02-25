package ir.fidar.pam.service.impl;

import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.ServiceNotSupportedException;
import ir.fidar.core.service.impl.generic.SingletonEntityGlobalServiceImpl;
import ir.fidar.pam.da.repository.SessionTimeoutSettingRepository;
import ir.fidar.pam.domain.dto.SessionTimeoutSettingReadDto;
import ir.fidar.pam.domain.dto.SessionTimeoutSettingUpdateDto;
import ir.fidar.pam.domain.model.SessionTimeoutSetting;
import ir.fidar.pam.service.SessionTimeoutSettingCrudService;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SessionTimeoutSettingCrudServiceImpl extends SingletonEntityGlobalServiceImpl<SessionTimeoutSetting> implements SessionTimeoutSettingCrudService {
   private final SessionTimeoutSettingRepository sessionTimeoutSettingRepository;

   public SessionTimeoutSettingCrudServiceImpl(SessionTimeoutSettingRepository sessionTimeoutSettingRepository) {
      super(sessionTimeoutSettingRepository);
      this.sessionTimeoutSettingRepository = sessionTimeoutSettingRepository;
   }

   @Override
   public Optional<DetailsDto> load() {
      SessionTimeoutSetting sessionTimeoutSetting = this.fetchRecord();
      SessionTimeoutSettingReadDto sessionTimeoutSettingReadDto = new SessionTimeoutSettingReadDto();
      sessionTimeoutSettingReadDto.setSshConnectionTimeout(sessionTimeoutSetting.getSshConnectionTimeout());
      sessionTimeoutSettingReadDto.setRdpConnectionTimeout(sessionTimeoutSetting.getRdpConnectionTimeout());
      sessionTimeoutSettingReadDto.setVncConnectionTimeout(sessionTimeoutSetting.getVncConnectionTimeout());
      sessionTimeoutSettingReadDto.setTelnetConnectionTimeout(sessionTimeoutSetting.getTelnetConnectionTimeout());
      sessionTimeoutSettingReadDto.setReactiveSshByMouseMovement(sessionTimeoutSetting.isReactiveSshByMouseMovement());
      sessionTimeoutSettingReadDto.setReactiveTelnetByMouseMovement(sessionTimeoutSetting.isReactiveTelnetByMouseMovement());
      AuditionInfoAndGlobalFieldsCopier.copy(sessionTimeoutSetting, sessionTimeoutSettingReadDto);
      return Optional.of(sessionTimeoutSettingReadDto);
   }

   public void create(SessionTimeoutSettingUpdateDto CreateDto) {
      throw new ServiceNotSupportedException();
   }

   @Transactional
   public void update(SessionTimeoutSettingUpdateDto sessionTimeoutSettingUpdateDto) {
      SessionTimeoutSetting sessionTimeoutSetting = this.fetchRecord();
      sessionTimeoutSetting.setSshConnectionTimeout(sessionTimeoutSettingUpdateDto.getSshConnectionTimeout());
      sessionTimeoutSetting.setRdpConnectionTimeout(sessionTimeoutSettingUpdateDto.getRdpConnectionTimeout());
      sessionTimeoutSetting.setVncConnectionTimeout(sessionTimeoutSettingUpdateDto.getVncConnectionTimeout());
      sessionTimeoutSetting.setTelnetConnectionTimeout(sessionTimeoutSettingUpdateDto.getTelnetConnectionTimeout());
      sessionTimeoutSetting.setReactiveSshByMouseMovement(sessionTimeoutSettingUpdateDto.isReactiveSshByMouseMovement());
      sessionTimeoutSetting.setReactiveTelnetByMouseMovement(sessionTimeoutSettingUpdateDto.isReactiveTelnetByMouseMovement());
      this.sessionTimeoutSettingRepository.save(sessionTimeoutSetting);
   }

   @Override
   public void delete() {
      throw new ServiceNotSupportedException();
   }
}
