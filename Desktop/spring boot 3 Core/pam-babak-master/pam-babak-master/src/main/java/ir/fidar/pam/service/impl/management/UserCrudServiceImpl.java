package ir.fidar.pam.service.impl.management;

import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.domain.dto.management.user.UserCreateDto;
import ir.fidar.core.domain.dto.management.user.UserDetailsDto;
import ir.fidar.core.domain.dto.management.user.UserUpdateDto;
import ir.fidar.core.domain.model.management.MessageHistory;
import ir.fidar.core.domain.model.management.UserGroup;
import ir.fidar.core.license.register.LicenseInterceptingPoint;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.security.sessionmanagement.AuthenticationAwareSessionInfo;
import ir.fidar.core.security.sessionmanagement.SessionService;
import ir.fidar.core.service.impl.management.user.AbstractUserCrudServiceImpl;
import ir.fidar.core.service.management.security.PasswordComplexitySettingService;
import ir.fidar.core.service.management.security.RoleService;
import ir.fidar.core.service.management.user.UserGroupService;
import ir.fidar.core.service.management.user.UserPropertyActivationDeactivationService;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.pam.da.repository.UserRepository;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.exception.IneligibleUserGroupAssignmentException;
import ir.fidar.pam.exception.IneligibleUserGroupMembershipException;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingRuleAssignmentException;
import ir.fidar.pam.exception.UserUserGroupAssignmentViolatingRuleAssignmentException;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.session.websocket.RemoteSessionUserCredentialStorageManager;
import java.util.ArrayList;
import java.util.List;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserCrudServiceImpl extends AbstractUserCrudServiceImpl<User, UserCreateDto, UserUpdateDto, UserDetailsDto> {
   private final RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager;
   private final AccessRuleService accessRuleService;

   public UserCrudServiceImpl(
      UserRepository userRepository,
      RoleService roleService,
      PasswordEncoder passwordEncoder,
      SessionService<AuthenticationAwareSessionInfo> sessionService,
      UserPropertyActivationDeactivationService userPropertyActivationDeactivationService,
      Validator validator,
      PasswordComplexitySettingService passwordComplexitySettingService,
      RemoteSessionUserCredentialStorageManager remoteSessionUserCredentialStorageManager,
      GenericCrudRepository<MessageHistory> messageHistoryCrudRepository,
      @Lazy AccessRuleService accessRuleService,
      SmsSender smsSender,
      EmailSender emailSender
   ) {
      super(
         userRepository,
         roleService,
         passwordEncoder,
         sessionService,
         userPropertyActivationDeactivationService,
         validator,
         passwordComplexitySettingService,
         messageHistoryCrudRepository,
         smsSender,
         emailSender
      );
      this.remoteSessionUserCredentialStorageManager = remoteSessionUserCredentialStorageManager;
      this.accessRuleService = accessRuleService;
   }

   @Autowired
   @Override
   public void setUserGroupService(UserGroupService userGroupService) {
      this.userGroupService = userGroupService;
   }

   @Override
   protected Class<User> getPersistingInstanceClass() {
      return User.class;
   }

   protected User processExtraChecksBeforeUpdate(User user, UserUpdateDto userUpdateDto) throws Exception {
      this.accessRuleService.validateUserUserGroupAssignment(user);
      List<FilterChain> userUserNameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("username", user.getUsername());

      for (UserGroup userGroup : user.getUserGroups()) {
         List<FilterChain> userGroupNameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroup.getName());
         this.validateRulesAssignment(userUserNameFilter, userGroupNameFilter, userGroup.getName());
         this.validateConnectionUniqueAccessibility(userGroupNameFilter, userUserNameFilter, userGroup.getName());
      }

      return user;
   }

   protected void processExtraChecksBeforeDelete(User user) {
      this.checkAssignedRulesAndRemoveIfRequired(user);
      this.removeStoredSessionCredentials(user);
   }

   @LicenseInterceptingPoint
   @Override
   public void create(UserCreateDto userCreateDto) throws Exception {
      super.create(userCreateDto);
   }

   private void validateRulesAssignment(List<FilterChain> userUsernameFilter, List<FilterChain> userGroupNameFilter, String userGroupName) throws UserGroupUserMembershipViolatingRuleAssignmentException, UserUserGroupAssignmentViolatingRuleAssignmentException {
      this.validateCaptureRulesAssignment(userUsernameFilter, userGroupNameFilter, userGroupName);
   }

   private void validateCaptureRulesAssignment(List<FilterChain> userUsernameFilter, List<FilterChain> userGroupNameFilter, String userGroupName) throws UserUserGroupAssignmentViolatingRuleAssignmentException {
      List<String> userGroupCaptureRuleNames = this.fetchAllRuleNamesOfUserGroup(userGroupNameFilter, CaptureRule.class);

      for (String userAccessRuleName : this.fetchAllRuleNamesOfUser(userUsernameFilter, CaptureRule.class)) {
         for (String userGroupCaptureRuleName : userGroupCaptureRuleNames) {
            if (userAccessRuleName.equalsIgnoreCase(userGroupCaptureRuleName)) {
               throw new UserUserGroupAssignmentViolatingRuleAssignmentException(userGroupName, userGroupCaptureRuleName, CaptureRule.class);
            }
         }
      }
   }

   private void validateConnectionUniqueAccessibility(List<FilterChain> userGroupNameFilter, List<FilterChain> userUsernameFilter, String userGroupName) throws IneligibleUserGroupMembershipException, IneligibleUserGroupAssignmentException {
      this.validateConnectionUniqueAccessibilityOfCaptureRules(userGroupNameFilter, userUsernameFilter, userGroupName);
   }

   private void validateConnectionUniqueAccessibilityOfCaptureRules(
      List<FilterChain> userGroupNameFilter, List<FilterChain> userUsernameFilter, String userGroupName
   ) throws IneligibleUserGroupMembershipException, IneligibleUserGroupAssignmentException {
      List<String[]> userGroupConnectionNames = this.fetchAllConnectionsWithCaptureRulesOfUserGroup(userGroupNameFilter);
      List<String[]> userConnectionNames = this.fetchAllConnectionsWithCaptureRulesOfUser(userUsernameFilter);
      this.validateConnectionUniqueAccessibility(userGroupConnectionNames, userConnectionNames, userGroupName, CaptureRule.class);
   }

   private void validateConnectionUniqueAccessibility(
      List<String[]> userGroupConnectionNames, List<String[]> userConnectionNames, String userGroupName, Class targetRule
   ) throws IneligibleUserGroupMembershipException, IneligibleUserGroupAssignmentException {
      for (String[] userGroupConnectionName : userGroupConnectionNames) {
         for (String[] userConnectionName : userConnectionNames) {
            if (!userGroupConnectionName[0].equalsIgnoreCase(userConnectionName[0]) && userGroupConnectionName[1].equalsIgnoreCase(userConnectionName[1])) {
               if (userConnectionName.length == 2) {
                  throw new IneligibleUserGroupAssignmentException(userGroupName, userConnectionName[0], userConnectionName[1], targetRule);
               }

               throw new IneligibleUserGroupAssignmentException(userGroupName, userConnectionName[0], userConnectionName[1], userConnectionName[2], targetRule);
            }
         }
      }
   }

   private List<String> fetchAllRuleNamesOfUser(List<FilterChain> userFilter, Class targetRule) {
      JpaQuery query = new JpaQueryBuilder().select("rule.name").from(targetRule, "rule").distinct().join("users", "u").on(userFilter).build();
      return this.jpaQueryBasedReadRepository.findAll(query, tuple -> tuple.get(0).toString());
   }

   private List<String> fetchAllRuleNamesOfUserGroup(List<FilterChain> userGroupFilter, Class targetRule) {
      JpaQuery query = new JpaQueryBuilder().select("rule.name").from(targetRule, "rule").distinct().join("userGroups", "ug").on(userGroupFilter).build();
      return this.jpaQueryBasedReadRepository.findAll(query, tuple -> tuple.get(0).toString());
   }

   private List<String[]> fetchAllConnectionsWithCaptureRulesOfUserGroup(List<FilterChain> userGroupFilter) {
      List<String[]> result = new ArrayList<>();
      JpaQuery query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(ir.fidar.pam.domain.model.management.UserGroup.class, "ug")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userGroupFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(ir.fidar.pam.domain.model.management.UserGroup.class, "ug")
         .join("captureRules", "cr")
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .where(userGroupFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      return result;
   }

   private List<String[]> fetchAllConnectionsWithCaptureRulesOfUser(List<FilterChain> userFilter) {
      List<String[]> result = new ArrayList<>();
      JpaQuery query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(ir.fidar.core.domain.model.management.User.class, "u")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(ir.fidar.core.domain.model.management.User.class, "u")
         .join("captureRules", "cr")
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name", "ug.name")
         .from(ir.fidar.core.domain.model.management.User.class, "u")
         .join("userGroups", "ug")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1), (String)tuple.get(2)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name", "ug.name")
         .from(ir.fidar.core.domain.model.management.User.class, "u")
         .join("userGroups", "ug")
         .join("captureRules", "cr")
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1), (String)tuple.get(2)}));
      return result;
   }

   private void checkAssignedRulesAndRemoveIfRequired(User user) {
   }

   private void removeStoredSessionCredentials(User user) {
      this.remoteSessionUserCredentialStorageManager.delete(user.getUsername());
   }
}
