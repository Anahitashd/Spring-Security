package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N14NewTableForResourceAccessInfo extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.3";
   }

   @Override
   public String getDescription() {
      return "Creating new tables 'tb_resource_access_info' and 'tb_resource_access_info_user'";
   }

   @Override
   public String getScriptName() {
      return "14.new_table_for_resource_access_info";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
