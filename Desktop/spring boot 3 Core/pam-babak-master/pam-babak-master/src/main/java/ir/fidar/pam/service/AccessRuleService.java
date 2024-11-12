package ir.fidar.pam.service;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.core.service.generic.GenericService;
import ir.fidar.pam.domain.dto.connection.ConnectionSessionInteractionModeDto;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.UserGroupUserMembershipViolatingRuleAssignmentException;
import ir.fidar.pam.exception.UserUserGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.UserUserGroupAssignmentViolatingRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;
import ir.fidar.pam.exception.connection.ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException;
import ir.fidar.pam.exception.connection.ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException;
import java.util.Set;

public interface AccessRuleService extends GenericService<AccessRule, String> {
   AccessRule getOneByName(String var1, boolean var2);

   AccessRule getOneByUuid(String var1);

   void addUser(String var1, User var2) throws AbstractException;

   void createNewRecord(String var1, String var2, String var3, Set<String> var4, Set<String> var5, boolean var6, FileTransferMode var7) throws Exception;

   void delete(Long var1);

   AccessRule getOneByUserAndConnection(long var1, long var3);

   AccessRuleConnection getConnectionSettings(Long var1, Long var2);

   ConnectionSessionInteractionModeDto resolveInteractionSettings(AccessRule var1, Connection var2);

   void validateUserGroupUserMembership(UserGroup var1) throws UserGroupUserMembershipViolatingRuleAssignmentException, UserGroupUserMembershipViolatingAccessRuleConnectionAccessibilityException;

   void validateUserUserGroupAssignment(User var1) throws UserUserGroupAssignmentViolatingRuleAssignmentException, UserUserGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;

   void validateConnectionGroupConnectionMembership(ConnectionGroup var1) throws ConnectionGroupConnectionMembershipViolatingAccessRuleAssignmentException, ConnectionGroupConnectionMembershipViolatingAccessRuleConnectionAccessibilityException;

   void validateConnectionConnectionGroupAssignment(Connection var1) throws ConnectionConnectionGroupAssignmentViolatingRuleAssignmentException, ConnectionConnectionGroupAssignmentViolatingAccessRuleConnectionAccessibilityException;
}
