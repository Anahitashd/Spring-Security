package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N12AddingNewColumnToAccessRule extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.1";
   }

   @Override
   public String getDescription() {
      return "Adding new column 'capture_disabled' to 'tb_access_rule' table";
   }

   @Override
   public String getScriptName() {
      return "12.new_column_for_access_rule";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
