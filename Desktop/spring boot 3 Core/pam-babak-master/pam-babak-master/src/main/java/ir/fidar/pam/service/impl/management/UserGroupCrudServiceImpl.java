package ir.fidar.pam.service.impl.management;

import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupCreateDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupDetailsDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupListDto;
import ir.fidar.core.domain.dto.management.usergroup.UserGroupUpdateDto;
import ir.fidar.core.domain.model.management.User;
import ir.fidar.core.service.impl.management.user.AbstractUserGroupCrudServiceImpl;
import ir.fidar.core.service.management.user.UserService;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.pam.da.repository.UserGroupRepository;
import ir.fidar.pam.domain.model.CaptureRule;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.exception.IneligibleUserGroupMembershipException;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingRuleAssignmentException;
import ir.fidar.pam.service.AccessRuleService;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;

@Service
public class UserGroupCrudServiceImpl
   extends AbstractUserGroupCrudServiceImpl<UserGroup, UserGroupCreateDto, UserGroupUpdateDto, UserGroupListDto, UserGroupDetailsDto> {
   private final AccessRuleService accessRuleService;

   public UserGroupCrudServiceImpl(UserGroupRepository userGroupRepository, @Lazy AccessRuleService accessRuleService) {
      super(userGroupRepository);
      this.accessRuleService = accessRuleService;
   }

   @Autowired
   @Override
   public void setUserService(UserService userService) {
      this.userService = userService;
   }

   @Override
   protected Class<UserGroup> getPersistingInstanceClass() {
      return UserGroup.class;
   }

   protected void processExtraChecksBeforeDelete(UserGroup userGroup) {
      this.checkAssignedRulesAndRemoveIfRequired(userGroup);
   }

   protected UserGroup processExtraChecksBeforeUpdate(UserGroup userGroup, UserGroupUpdateDto userGroupUpdateDto) throws Exception {
      this.accessRuleService.validateUserGroupUserMembership(userGroup);
      List<FilterChain> userGroupNameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("name", userGroup.getName());

      for (User user : userGroup.getUsers()) {
         List<FilterChain> userUsernameFilter = QueryAndFilterUtils.caseInsensitiveStringFilter("username", user.getUsername());
         this.validateRulesAssignment(userUsernameFilter, userGroupNameFilter, user.getUsername());
         this.validateConnectionUniqueAccessibility(userGroupNameFilter, userUsernameFilter, user.getUsername());
      }

      return userGroup;
   }

   private void validateRulesAssignment(List<FilterChain> userUsernameFilter, List<FilterChain> userGroupNameFilter, String username) throws UserGroupUserMembershipViolatingRuleAssignmentException {
      this.validateCaptureRulesAssignment(userUsernameFilter, userGroupNameFilter, username);
   }

   private void validateCaptureRulesAssignment(List<FilterChain> userUsernameFilter, List<FilterChain> userGroupNameFilter, String username) throws UserGroupUserMembershipViolatingRuleAssignmentException {
      List<String> userGroupCaptureRuleNames = this.fetchAllRuleNamesOfUserGroup(userGroupNameFilter, CaptureRule.class);

      for (String userAccessRuleName : this.fetchAllRuleNamesOfUser(userUsernameFilter, CaptureRule.class)) {
         for (String userGroupCaptureRuleName : userGroupCaptureRuleNames) {
            if (userAccessRuleName.equalsIgnoreCase(userGroupCaptureRuleName)) {
               throw new UserGroupUserMembershipViolatingRuleAssignmentException(username, userGroupCaptureRuleName, CaptureRule.class);
            }
         }
      }
   }

   private void validateConnectionUniqueAccessibility(List<FilterChain> userGroupNameFilter, List<FilterChain> userUsernameFilter, String username) throws IneligibleUserGroupMembershipException {
      this.validateConnectionUniqueAccessibilityOfCaptureRules(userGroupNameFilter, userUsernameFilter, username);
   }

   private void validateConnectionUniqueAccessibilityOfCaptureRules(
      List<FilterChain> userGroupNameFilter, List<FilterChain> userUsernameFilter, String username
   ) throws IneligibleUserGroupMembershipException {
      List<String[]> userGroupConnectionNames = this.fetchAllConnectionsWithCaptureRulesOfUserGroup(userGroupNameFilter);
      List<String[]> userConnectionNames = this.fetchAllConnectionsWithCaptureRulesOfUser(userUsernameFilter);
      this.validateConnectionUniqueAccessibility(userGroupConnectionNames, userConnectionNames, username, CaptureRule.class);
   }

   private void validateConnectionUniqueAccessibility(
      List<String[]> userGroupConnectionNames, List<String[]> userConnectionNames, String username, Class targetRule
   ) throws IneligibleUserGroupMembershipException {
      for (String[] userGroupConnectionName : userGroupConnectionNames) {
         for (String[] userConnectionName : userConnectionNames) {
            if (!userGroupConnectionName[0].equalsIgnoreCase(userConnectionName[0]) && userGroupConnectionName[1].equalsIgnoreCase(userConnectionName[1])) {
               if (userConnectionName.length == 2) {
                  throw new IneligibleUserGroupMembershipException(username, userConnectionName[0], userConnectionName[1], targetRule);
               }

               throw new IneligibleUserGroupMembershipException(username, userConnectionName[0], userConnectionName[1], userConnectionName[2], targetRule);
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
         .from(UserGroup.class, "ug")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userGroupFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(UserGroup.class, "ug")
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
         .from(User.class, "u")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name")
         .from(User.class, "u")
         .join("captureRules", "cr")
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name", "ug.name")
         .from(User.class, "u")
         .join("userGroups", "ug")
         .join("captureRules", "cr")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1), (String)tuple.get(2)}));
      query = new JpaQueryBuilder()
         .select("cr.name", "c.name", "ug.name")
         .from(User.class, "u")
         .join("userGroups", "ug")
         .join("captureRules", "cr")
         .join("connectionGroups", "cg")
         .join("connections", "c")
         .where(userFilter)
         .build();
      result.addAll(this.jpaQueryBasedReadRepository.findAll(query, tuple -> new String[]{(String)tuple.get(0), (String)tuple.get(1), (String)tuple.get(2)}));
      return result;
   }

   private void checkAssignedRulesAndRemoveIfRequired(UserGroup userGroup) {
   }
}
