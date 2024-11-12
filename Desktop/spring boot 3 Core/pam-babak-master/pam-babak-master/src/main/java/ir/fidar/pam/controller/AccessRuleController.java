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
import ir.fidar.pam.domain.dto.accessrule.AccessRuleCreateDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleUpdateDto;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.exception.accessrule.AccessRuleDisabledException;
import ir.fidar.pam.exception.accessrule.AccessRuleExpiredException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import ir.fidar.pam.service.AccessRuleCrudService;
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
@RequestMapping({"/api/access-rules"})
public class AccessRuleController extends GenericCrudController<String, AccessRuleCreateDto, AccessRuleUpdateDto> {
   private final AccessRuleCrudService accessRuleCrudService;

   public AccessRuleController(@Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService) {
      super(accessRuleCrudService);
      this.accessRuleCrudService = accessRuleCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllAccessRules(
      @Filter(AccessRule.class) List<LinkedFilter> filters,
      @Sort(value = AccessRule.class,ignoringAbsentProperties = {"cname", "ipAddress", "port", "type"}) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllAccessRules(
      @Filter(AccessRule.class) List<LinkedFilter> filters,
      @Pagination Pageable pageable,
      @Sort(value = AccessRule.class,ignoringAbsentProperties = {"cname", "ipAddress", "port", "type"}) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @GetMapping({"/connection-info/{connection}"})
   public ResponseEntity<Response> getConditionsOfSpecificAccessRule(@PathVariable(name = "connection") String connectionName) throws InsufficientPrivilegeToAccessSessionException, AccessRuleDisabledException, AccessRuleExpiredException {
      return ResponseEntity.ok(Response.success("access_rule.conditions.read", this.accessRuleCrudService.loadConditionInfo(connectionName)));
   }
}
