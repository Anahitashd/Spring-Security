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
import ir.fidar.pam.domain.dto.connection.create.ConnectionCreateDto;
import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.exception.connection.RemoteApplicationOnlySupportedByRdpConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.service.AccessRuleCrudService;
import ir.fidar.pam.service.CaptureRuleCrudService;
import ir.fidar.pam.service.connection.ConnectionCrudService;
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
@RequestMapping({"/api/connections"})
public class ConnectionController extends GenericCrudController<String, ConnectionCreateDto, ConnectionUpdateDto> {
   private final ConnectionCrudService connectionCrudService;
   private final AccessRuleCrudService accessRuleCrudService;
   private final CaptureRuleCrudService captureRuleCrudService;

   public ConnectionController(
      @Qualifier("connectionCrudServiceImpl") ConnectionCrudService connectionCrudService,
      @Qualifier("accessRuleCrudServiceImpl") AccessRuleCrudService accessRuleCrudService,
      @Qualifier("captureRuleCrudServiceImpl") CaptureRuleCrudService captureRuleCrudService
   ) {
      super(connectionCrudService);
      this.connectionCrudService = connectionCrudService;
      this.accessRuleCrudService = accessRuleCrudService;
      this.captureRuleCrudService = captureRuleCrudService;
   }

   @GetMapping
   public ResponseEntity<Response> getAllConnections(@Filter(Connection.class) List<LinkedFilter> filters, @Sort(Connection.class) Sorting sorting) {
      return ResponseEntity.ok(Response.Crud.get(this.connectionCrudService.load(filters, sorting).orElse(Collections.emptyList())));
   }

   @GetMapping(
      params = {"page"}
   )
   public ResponseEntity<Response> getAllConnections(
      @Filter(Connection.class) List<LinkedFilter> filters, @Pagination Pageable pageable, @Sort(Connection.class) Sorting sorting
   ) throws InvalidPageException {
      return ResponseEntity.ok(Response.Crud.get(this.connectionCrudService.load(filters, pageable, sorting).orElse(PagingUtil.emptyCustomPage())));
   }

   @GetMapping({"/{name}/credentials"})
   public ResponseEntity<Response> getCredentialsOfSpecificConnection(@PathVariable(name = "name") String connectionName) {
      return ResponseEntity.ok(
         Response.Crud.get(this.connectionCrudService.loadCredentialsOfSpecificConnection(connectionName).orElse(Collections.emptyList()))
      );
   }

   @GetMapping({"/{name}/services"})
   public ResponseEntity<Response> getServicesOfSpecificConnection(@PathVariable(name = "name") String connectionName) {
      return ResponseEntity.ok(Response.Crud.get(this.connectionCrudService.loadServicesOfSpecificConnection(connectionName).get()));
   }

   @GetMapping({"/{name}/capture-rules/privileges"})
   public ResponseEntity<Response> getCapturingPrivilegesOfCurrentUserOverConnection(@PathVariable(name = "name") String connectionName) throws InsufficientPrivilegeToAccessCaptureException {
      return ResponseEntity.ok(
         Response.Crud.get(this.connectionCrudService.loadCapturePrivilegesOfCurrentUserOnSpecificConnection(connectionName).orElse(null))
      );
   }

   @GetMapping({"/{name}/access-rules"})
   public ResponseEntity<Response> getAllAccessRulesOfSpecificUserGroup(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.accessRuleCrudService.loadAccessRulesSetOverSpecificConnection(name)));
   }

   @GetMapping({"/{name}/capture-rules"})
   public ResponseEntity<Response> getAllCaptureRulesOfSpecificUser(@PathVariable(name = "name") String name) {
      return ResponseEntity.ok(Response.Crud.get(this.captureRuleCrudService.loadCaptureRulesSetOverSpecificConnection(name)));
   }

   @GetMapping({"/{name}/remote-applications"})
   public ResponseEntity<Response> getRemoteApplicationsOfSpecificConnection(@PathVariable(name = "name") String connectionName) throws RemoteApplicationOnlySupportedByRdpConnectionException {
      return ResponseEntity.ok(
         Response.Crud.get(this.connectionCrudService.loadRemoteApplicationsOfSpecificConnection(connectionName).orElse(Collections.emptyList()))
      );
   }
}
