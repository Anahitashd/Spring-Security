package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N19CreatingTransparentCaptureTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.8";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_transparent_capture`, add `transparent_port` to `tb_connection`";
   }

   @Override
   public String getScriptName() {
      return "19.transparent_capture_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
