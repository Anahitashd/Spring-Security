package ir.fidar.pam.controller.management;

import ir.fidar.core.controller.management.AbstractUserController;
import ir.fidar.core.domain.dto.management.user.UserCreateDto;
import ir.fidar.core.domain.dto.management.user.UserUpdateDto;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.service.management.user.UserCrudService;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.CaptureRuleCrudService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/management/users"})
public class UserController extends AbstractUserController<UserCreateDto, UserUpdateDto> {
   private final AccessRuleCrudService accessRuleCrudService;
   private final CaptureRuleCrudService captureRuleCrudService;

   public UserController(
      @Qualifier("userCrudServiceImpl") UserCrudService userCrudService,
      @Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService,
      @Qualifier("captureRuleCrudServiceImpl") CaptureRuleCrudService captureRuleCrudService
   ) {
      super(userCrudService);
      this.accessRuleCrudService = accessRuleCrudService;
      this.captureRuleCrudService = captureRuleCrudService;
   }

   @GetMapping({"/{username}/access-rules"})
   public ResponseEntity<Response> getAllAccessRulesOfSpecificUser(@PathVariable(name = "username") String username) {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.loadAccessRulesAssignedToSpecificUser(username)));
   }

   @GetMapping({"/{username}/capture-rules"})
   public ResponseEntity<Response> getAllCaptureRulesOfSpecificUser(@PathVariable(name = "username") String username) {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.loadCaptureRulesAssignedToSpecificUser(username)));
   }
}
