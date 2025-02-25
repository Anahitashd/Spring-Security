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
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoCreateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoUpdateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.SharedResourceAccessInfoUpdateDto;
import ir.fidar.pam.domain.model.ResourceAccessInfo;
import ir.fidar.pam.exception.resourceaccessinfo.ResourceAccessInfoNoInfoProvidedException;
import ir.fidar.pam.exception.resourceaccessinfo.UnprivilegedSharedResourceAccessInfoEditionException;
import ir.fidar.pam.service.ResourceAccessInfoCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(
   path = {"/api/resource-access-info"}
)
public class ResourceAccessInfoController extends GenericCrudController<String, ResourceAccessInfoCreateDto, ResourceAccessInfoUpdateDto> {
   private ResourceAccessInfoCrudService resourceAccessInfoCrudService;

   public ResourceAccessInfoController(@Qualifier("resourceAccessInfoCrudServiceImpl") ResourceAccessInfoCrudService resourceAccessInfoCrudService) {
      super(resourceAccessInfoCrudService);
      this.resourceAccessInfoCrudService = resourceAccessInfoCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllResourceAccessInfo(
      @Filter(ResourceAccessInfo.class) List<LinkedFilter> filters, @Sort(ResourceAccessInfo.class) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.resourceAccessInfoCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllResourceAccessInfoByPage(
      @Filter(ResourceAccessInfo.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(ResourceAccessInfo.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.resourceAccessInfoCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @GetMapping(
      path = {"/shared-resources"}
   )
   public ResponseEntity<Response> getAllSharedResourceAccessInfo(
      @Filter(ResourceAccessInfo.class) List<LinkedFilter> filters, @Sort(ResourceAccessInfo.class) Sorting sorting
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.resourceAccessInfoCrudService.loadSharedResources(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      path = {"/shared-resources"},
      params = {"page"}
   )
   public ResponseEntity<Response> getAllSharedResourceAccessInfoByPage(
      @Filter(ResourceAccessInfo.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(ResourceAccessInfo.class) Sorting sorting
   ) {
      return ResponseEntity.ok(
         Response.Crud.get(this.resourceAccessInfoCrudService.loadSharedResources(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage()))
      );
   }

   @PutMapping(
      path = {"/shared-resources"}
   )
   public ResponseEntity<Response> updateSharedResourceAccessInfo(@RequestBody SharedResourceAccessInfoUpdateDto sharedResourceAccessInfoUpdateDto) throws UnprivilegedSharedResourceAccessInfoEditionException, ResourceAccessInfoNoInfoProvidedException {
      this.resourceAccessInfoCrudService.updateSharedResource(sharedResourceAccessInfoUpdateDto);
      return ResponseEntity.ok(Response.Crud.update());
   }
}
