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
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintCreateDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintUpdateDto;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.service.SessionInputConstraintCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/session-input-constraints"})
public class SessionInputConstraintController extends GenericCrudController<String, SessionInputConstraintCreateDto, SessionInputConstraintUpdateDto> {
   private final SessionInputConstraintCrudService sessionInputConstraintCrudService;

   public SessionInputConstraintController(
      @Qualifier("sessionInputConstraintCrudServiceImpl") SessionInputConstraintCrudService sessionInputConstraintCrudService
   ) {
      super(sessionInputConstraintCrudService);
      this.sessionInputConstraintCrudService = sessionInputConstraintCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllSessionInputConstraints(
      @Filter(SessionInputConstraint.class) List<LinkedFilter> filters, @Sort(SessionInputConstraint.class) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.sessionInputConstraintCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllSessionInputConstraints(
      @Filter(SessionInputConstraint.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(SessionInputConstraint.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.sessionInputConstraintCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }
}
