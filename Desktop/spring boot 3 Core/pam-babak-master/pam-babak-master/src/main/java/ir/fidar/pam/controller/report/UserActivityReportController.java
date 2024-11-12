package ir.fidar.pam.controller.report;

import ir.fidar.core.management.response.Response;
import ir.fidar.core.security.validation.CustomizedXssProtected;
import ir.fidar.pam.domain.type.TimeUnit;
import ir.fidar.pam.service.report.UserActivityReportService;
import jakarta.validation.constraints.Min;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(
   path = {"/api/reports/user-activity"}
)
public class UserActivityReportController {
   private final UserActivityReportService userActivityReportService;

   public UserActivityReportController(UserActivityReportService userActivityReportService) {
      this.userActivityReportService = userActivityReportService;
   }

   @GetMapping(
      path = {"authentication-attempts"},
      params = {"unit", "count"}
   )
   public ResponseEntity<Response> getAuthenticationAttemptsCount(
      @RequestParam(name = "unit",required = false,defaultValue = "DAY") TimeUnit timeUnit,
      @Min(value = 1L,message = "lt_min.count") @RequestParam(name = "count",required = false,defaultValue = "10") int count
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveAuthenticationAttemptsInLastUnitTime(timeUnit, count)));
   }

   @GetMapping(
      path = {"authentication-attempts"},
      params = {"username", "unit", "count"}
   )
   public ResponseEntity<Response> getAuthenticationAttemptsCountForSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username,
      @RequestParam(name = "unit",required = false,defaultValue = "DAY") TimeUnit timeUnit,
      @Min(value = 1L,message = "lt_min.count") @RequestParam(name = "count",required = false,defaultValue = "10") int count
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveAuthenticationAttemptsInLastUnitTime(username, timeUnit, count)));
   }

   @GetMapping(
      path = {"authentication-attempts"},
      params = {"username"}
   )
   public ResponseEntity<Response> getAuthenticationAttemptsCountForSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveTotalAuthenticationAttempts(username)));
   }

   @GetMapping(
      path = {"session-count-per-type"},
      params = {"username"}
   )
   public ResponseEntity<Response> getTotalSessionCountsPerTypeForSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveSessionCountsPerType(username)));
   }

   @GetMapping(
      path = {"session-count-per-type"},
      params = {"username", "unit", "count"}
   )
   public ResponseEntity<Response> getTotalSessionCountsPerTypeForSpecificUserBaseOnTime(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username,
      @RequestParam(name = "unit",required = false,defaultValue = "DAY") TimeUnit timeUnit,
      @Min(value = 1L,message = "lt_min.count") @RequestParam(name = "count",required = false,defaultValue = "10") int count
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveSessionCountsPerTypeBaseOnTime(username, timeUnit, count)));
   }

   @GetMapping(
      path = {"remote-session-transferred-files"},
      params = {"username"}
   )
   public ResponseEntity<Response> getRemoteSessionTransferredFilesForSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveUserTransferredFilesOverRemoteSessions(username)));
   }

   @GetMapping(
      path = {"remote-session-constraint-violations"},
      params = {"username"}
   )
   public ResponseEntity<Response> getRemoteSessionConstraintViolationsForSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveUserConstraintViolationsOverRemoteSessions(username)));
   }

   @GetMapping(
      path = {"remote-session-duration"},
      params = {"count"}
   )
   public ResponseEntity<Response> getLastRemoteSessionsDurationOfSpecificUser(@RequestParam(name = "count",required = false,defaultValue = "20") int count) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveLastNRemoteSessionDuration(count)));
   }

   @GetMapping(
      path = {"remote-session-duration"},
      params = {"username", "count"}
   )
   public ResponseEntity<Response> getLastRemoteSessionsDurationOfSpecificUser(
      @CustomizedXssProtected(skippingCharacters = {'\\'}) @RequestParam(name = "username") String username,
      @RequestParam(name = "count",required = false,defaultValue = "20") int count
   ) {
      return ResponseEntity.ok(Response.Crud.get(this.userActivityReportService.retrieveUserLastNRemoteSessionDuration(username, count)));
   }
}
