package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N13AddingNewColumnsToRdpConnectionAndCapture extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.2";
   }

   @Override
   public String getDescription() {
      return "Adding new columns 'transparent_port' and 'transparent' to 'tb_rdp_connection' and 'tb_capture' tables respectively";
   }

   @Override
   public String getScriptName() {
      return "13.new_column_for_rdp_connection_and_capture";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
