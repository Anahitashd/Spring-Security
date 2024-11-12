package ir.fidar.pam.domain.model.management;

import ir.fidar.core.domain.dto.management.user.UserCreateDto;
import ir.fidar.core.domain.dto.management.user.UserUpdateDto;
import ir.fidar.core.management.log.crud.EnableAutoCrudLogging;
import ir.fidar.core.security.authorization.model.CrudRequest;
import ir.fidar.core.security.authorization.model.HttpMethod;
import ir.fidar.core.security.authorization.model.annotations.CrudPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Dependency;
import ir.fidar.core.security.authorization.model.annotations.DependencyList;
import ir.fidar.core.security.authorization.model.annotations.Secure;
import ir.fidar.core.security.authorization.model.annotations.Source;
import ir.fidar.core.security.authorization.model.annotations.SpecialPrivilege;
import ir.fidar.core.security.authorization.model.annotations.Target;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.ConnectionAccessRequest;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.service.impl.management.UserCrudServiceImpl;
import java.util.HashSet;
import java.util.Set;
import jakarta.persistence.CascadeType;
import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

@Secure(
   section = "USER",
   crud = @CrudPrivilege(
      baseURLs = {"/api/management/users/*", "/api/management/user-groups/*", "/api/management/users/import/active-directory"},
      requests = {CrudRequest.ALL}
   ),
   special = {@SpecialPrivilege(
      name = "CHANGE_OWN_PASS",
      baseURLs = {"/api/management/users/current-user/change-password"},
      allowedMethods = {HttpMethod.PUT}
   ), @SpecialPrivilege(
      name = "UPDATE_OWN_PROFILE",
      baseURLs = {"/api/management/users/current-user/profile", "/api/management/users/current-user/email/activation/*", "/api/management/users/current-user/email/deactivation/*", "/api/management/users/current-user/phone-number/activation/*", "/api/management/users/current-user/phone-number/deactivation/*"},
      allowedMethods = {HttpMethod.PUT, HttpMethod.GET, HttpMethod.POST}
   ), @SpecialPrivilege(
      name = "RESET_PASSWORD",
      baseURLs = {"/api/management/users/reset-password"},
      allowedMethods = {HttpMethod.PUT}
   ), @SpecialPrivilege(
      name = "CHANGE_TWO_FA",
      baseURLs = {"/api/management/users/current-user/two-factor-authentication/activation/*", "/api/management/users/current-user/two-factor-authentication/deactivation/*"},
      allowedMethods = {HttpMethod.POST, HttpMethod.GET}
   )},
   dependencies = @DependencyList({@Dependency(
         source = @Source(
            cruds = {CrudRequest.CREATE, CrudRequest.UPDATE}
         ),
         target = @Target(
            section = "ROLE",
            cruds = {CrudRequest.READ}
         )
      )})
)
@EnableAutoCrudLogging(
   displayName = "User",
   crudServiceImpl = UserCrudServiceImpl.class,
   createDto = UserCreateDto.class,
   updateDto = UserUpdateDto.class,
   uniquePropertyName = "username",
   isUniquePropertyImmutable = true
)
@Entity
@Table(
   name = "tb_user"
)
@DiscriminatorValue("1")
public class User extends ir.fidar.core.domain.model.management.User {
   @ManyToMany(
      mappedBy = "users",
      fetch = FetchType.LAZY
   )
   private Set<AccessRule> accessRules;
   @ManyToMany(
      mappedBy = "users",
      fetch = FetchType.LAZY
   )
   private Set<CaptureRule> captureRules;
   @OneToMany(
      mappedBy = "user",
      fetch = FetchType.LAZY,
      cascade = {CascadeType.ALL}
   )
   private Set<ConnectionAccessRequest> connectionAccessRequests = new HashSet<>();

   public Set<AccessRule> getAccessRules() {
      return this.accessRules;
   }

   public Set<CaptureRule> getCaptureRules() {
      return this.captureRules;
   }

   public Set<ConnectionAccessRequest> getConnectionAccessRequests() {
      return this.connectionAccessRequests;
   }

   public void addConnectionAccessRequest(ConnectionAccessRequest connectionAccessRequest) {
      this.connectionAccessRequests.add(connectionAccessRequest);
   }

   public void removeConnectionAccessRequest(ConnectionAccessRequest connectionAccessRequest) {
      this.connectionAccessRequests.remove(connectionAccessRequest);
   }

   @Override
   public boolean equals(Object o) {
      return super.equals(o);
   }

   @Override
   public int hashCode() {
      return super.hashCode();
   }
}
