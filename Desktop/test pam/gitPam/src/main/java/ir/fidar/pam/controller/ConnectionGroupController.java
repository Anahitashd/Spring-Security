package ir.fidar.pam.controller;

import ir.fidar.core.controller.generic.GenericCrudController;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.annotation.Pagination;
import ir.fidar.core.domain.annotation.Sort;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.management.response.Response;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.core.util.filter.web.resolver.Filter;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupCreateDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupUpdateDto;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.CaptureRuleCrudService;
import ir.fidar.pam.service.connection.ConnectionGroupCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/connection-groups"})
public class ConnectionGroupController extends GenericCrudController<String, ConnectionGroupCreateDto, ConnectionGroupUpdateDto> {
   private final ConnectionGroupCrudService connectionGroupCrudService;
   private final CaptureRuleCrudService captureRuleCrudService;
   private final AccessRuleCrudService accessRuleCrudService;

   public ConnectionGroupController(
      @Qualifier("connectionGroupCrudServiceImpl") ConnectionGroupCrudService connectionGroupCrudService,
      @Qualifier("captureRuleCrudServiceImpl") CaptureRuleCrudService captureRuleCrudService,
      @Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService
   ) {
      super(connectionGroupCrudService);
      this.connectionGroupCrudService = connectionGroupCrudService;
      this.captureRuleCrudService = captureRuleCrudService;
      this.accessRuleCrudService = accessRuleCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllConnectionGroups(
      @Filter(ConnectionGroup.class) List<LinkedFilter> filters, @Sort(ConnectionGroup.class) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.connectionGroupCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllConnectionGroups(
      @Filter(ConnectionGroup.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(ConnectionGroup.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.connectionGroupCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @GetMapping({"/{name}/capture-rules"})
   public ResponseEntity<Response> getAllCaptureRulesOfSpecificConnectionGroup(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.loadCaptureRulesSetOverSpecificConnectionGroup(name)));
   }

   @GetMapping({"/{name}/access-rules"})
   public ResponseEntity<Response> getAllAccessRulesOfSpecificConnectionGroup(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.loadAccessRulesSetOverSpecificConnectionGroup(name)));
   }
}
