package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N22RefactoringSessionScanningTransferredFileColumn extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.1";
   }

   @Override
   public String getDescription() {
      return "Remove column 'multi_av_scanner_record_id' and add new column 'kavosh_request_identifier' to 'tb_session_scanning_transferred_file' table";
   }

   @Override
   public String getScriptName() {
      return "22.refactor_session_scanning_transferred_file_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
