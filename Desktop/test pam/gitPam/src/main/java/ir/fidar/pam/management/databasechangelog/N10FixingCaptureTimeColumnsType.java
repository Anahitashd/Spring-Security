package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N10FixingCaptureTimeColumnsType extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.9";
   }

   @Override
   public String getDescription() {
      return "Changing `tb_capture` table's 'start_time' and 'end_time' columns type to 'INT UNSIGNED'";
   }

   @Override
   public String getScriptName() {
      return "10.fix_capture_time_columns_type";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
