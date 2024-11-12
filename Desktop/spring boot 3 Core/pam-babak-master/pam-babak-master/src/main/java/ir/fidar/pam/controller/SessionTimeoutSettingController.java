package ir.fidar.pam.controller;

import ir.fidar.core.controller.generic.SingletonGenericCrudController;
import ir.fidar.pam.domain.dto.SessionTimeoutSettingUpdateDto;
import ir.fidar.pam.service.SessionTimeoutSettingCrudService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/settings/session-timeout"})
public class SessionTimeoutSettingController extends SingletonGenericCrudController<SessionTimeoutSettingUpdateDto, SessionTimeoutSettingUpdateDto> {
   public SessionTimeoutSettingController(@Qualifier("sessionTimeoutSettingCrudServiceImpl") SessionTimeoutSettingCrudService sessionTimeoutSettingCrudService) {
      super(sessionTimeoutSettingCrudService);
   }
}
