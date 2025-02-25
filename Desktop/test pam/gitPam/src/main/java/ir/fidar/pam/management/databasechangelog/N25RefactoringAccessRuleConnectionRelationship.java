package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N25RefactoringAccessRuleConnectionRelationship extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.4";
   }

   @Override
   public String getDescription() {
      return "Refactor relationship of access-rule and connection";
   }

   @Override
   public String getScriptName() {
      return "25.refactoring_access_rule_connection_relationship";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
