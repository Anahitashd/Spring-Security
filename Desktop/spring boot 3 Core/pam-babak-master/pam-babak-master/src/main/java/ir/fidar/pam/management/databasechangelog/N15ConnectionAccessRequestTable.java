package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N15ConnectionAccessRequestTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.4";
   }

   @Override
   public String getDescription() {
      return "Creating new table 'tb_connection_access_request'";
   }

   @Override
   public String getScriptName() {
      return "15.connection_access_request_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
