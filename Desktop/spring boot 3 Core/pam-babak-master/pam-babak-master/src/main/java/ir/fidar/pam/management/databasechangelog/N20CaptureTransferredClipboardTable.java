package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N20CaptureTransferredClipboardTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.9";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_capture_transferred_clipboard`";
   }

   @Override
   public String getScriptName() {
      return "20.capture_transferred_clipboard_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
