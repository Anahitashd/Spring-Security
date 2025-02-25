package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N26RefactoringConnectionTransparentPortColumn extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.5";
   }

   @Override
   public String getDescription() {
      return "Refactor 'transparent_port' column's constraint in 'tb_connection' table";
   }

   @Override
   public String getScriptName() {
      return "26.refactoring_connection_transparent_port_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
