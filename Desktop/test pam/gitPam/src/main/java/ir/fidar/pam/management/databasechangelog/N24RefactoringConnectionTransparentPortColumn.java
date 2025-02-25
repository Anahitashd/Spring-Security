package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N24RefactoringConnectionTransparentPortColumn extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.3";
   }

   @Override
   public String getDescription() {
      return "Refactor 'transparent_port' column's constraint";
   }

   @Override
   public String getScriptName() {
      return "24.refactoring_connection_transparent_port_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
