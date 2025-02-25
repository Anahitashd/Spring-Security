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
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestCreateDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestReviewDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestUpdateDto;
import ir.fidar.pam.domain.model.ConnectionAccessRequest;
import ir.fidar.pam.service.ConnectionAccessRequestCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(
   path = {"/api/connection-access-requests"}
)
public class ConnectionAccessRequestController extends GenericCrudController<String, ConnectionAccessRequestCreateDto, ConnectionAccessRequestUpdateDto> {
   private final ConnectionAccessRequestCrudService connectionAccessRequestCrudService;

   public ConnectionAccessRequestController(
      @Qualifier("connectionAccessRequestCrudServiceImpl") ConnectionAccessRequestCrudService connectionAccessRequestCrudService
   ) {
      super(connectionAccessRequestCrudService);
      this.connectionAccessRequestCrudService = connectionAccessRequestCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllConnectionAccessRequests(
      @Filter(ConnectionAccessRequest.class) List<LinkedFilter> filters, @Sort(ConnectionAccessRequest.class) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.connectionAccessRequestCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllConnectionAccessRequests(
      @Filter(ConnectionAccessRequest.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(ConnectionAccessRequest.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.connectionAccessRequestCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @PutMapping(
      path = {"{identifier}/review"}
   )
   public ResponseEntity<Response> checkAccessRequest(
      @PathVariable(name = "identifier") String identifier, @RequestBody ConnectionAccessRequestReviewDto connectionAccessRequestReviewDto
   ) throws Exception {
      this.connectionAccessRequestCrudService.reviewRequest(identifier, connectionAccessRequestReviewDto);
      return ResponseEntity.ok(Response.success("con_access_req.reviewed.read"));
   }
}
