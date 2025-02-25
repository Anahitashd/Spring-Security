package ir.fidar.pam.controller.management;

import ir.fidar.core.controller.management.AbstractUserGroupController;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupCreateDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupUpdateDto;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.service.management.user.UserGroupCrudService;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.CaptureRuleCrudService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/management/user-groups"})
public class UserGroupController extends AbstractUserGroupController<UserGroupCreateDto, UserGroupUpdateDto> {
   private final AccessRuleCrudService accessRuleCrudService;
   private final CaptureRuleCrudService captureRuleCrudService;

   public UserGroupController(
      @Qualifier("userGroupCrudServiceImpl") UserGroupCrudService userGroupCrudService,
      @Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService,
      @Qualifier("captureRuleCrudServiceImpl") CaptureRuleCrudService captureRuleCrudService
   ) {
      super(userGroupCrudService);
      this.accessRuleCrudService = accessRuleCrudService;
      this.captureRuleCrudService = captureRuleCrudService;
   }

   @GetMapping({"/{name}/access-rules"})
   public ResponseEntity<Response> getAllAccessRulesOfSpecificUserGroup(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.loadAccessRulesAssignedToSpecificUserGroup(name)));
   }

   @GetMapping({"/{name}/capture-rules"})
   public ResponseEntity<Response> getAllCaptureRulesOfSpecificUser(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.loadCaptureRulesAssignedToSpecificUserGroup(name)));
   }
}
