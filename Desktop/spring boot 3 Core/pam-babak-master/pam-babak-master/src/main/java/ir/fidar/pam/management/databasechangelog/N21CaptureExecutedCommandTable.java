package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N21CaptureExecutedCommandTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.0";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_capture_executed_command`";
   }

   @Override
   public String getScriptName() {
      return "21.capture_executed_command_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
