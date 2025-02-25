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
import ir.fidar.pam.domain.dto.bridge.BridgeCreateDto;
import ir.fidar.pam.domain.dto.bridge.BridgeUpdateDto;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.service.BridgeCrudService;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/bridges"})
public class BridgeController extends GenericCrudController<String, BridgeCreateDto, BridgeUpdateDto> {
   private final BridgeCrudService bridgeCrudService;

   public BridgeController(@Qualifier("bridgeCrudServiceImpl") BridgeCrudService bridgeCrudService) {
      super(bridgeCrudService);
      this.bridgeCrudService = bridgeCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllBridges(@Filter(Bridge.class) List<LinkedFilter> filters, @Sort(Bridge.class) Sorting sorting) {
      return ResponseEntity.ok(Response.Crud.get(this.bridgeCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllBridges(
      @Filter(Bridge.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(Bridge.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.bridgeCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }
}
