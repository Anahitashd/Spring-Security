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
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleCreateDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleUpdateDto;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.service.CaptureRuleCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/capture-rules"})
public class CaptureRuleController extends GenericCrudController<String, CaptureRuleCreateDto, CaptureRuleUpdateDto> {
   private final CaptureRuleCrudService captureRuleCrudService;

   public CaptureRuleController(@Qualifier("captureRuleCrudServiceImpl") CaptureRuleCrudService captureRuleCrudService) {
      super(captureRuleCrudService);
      this.captureRuleCrudService = captureRuleCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllCaptureRules(@Filter(CaptureRule.class) List<LinkedFilter> filters, @Sort(CaptureRule.class) Sorting sorting) {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllCaptureRules(
      @Filter(CaptureRule.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(CaptureRule.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }
}
