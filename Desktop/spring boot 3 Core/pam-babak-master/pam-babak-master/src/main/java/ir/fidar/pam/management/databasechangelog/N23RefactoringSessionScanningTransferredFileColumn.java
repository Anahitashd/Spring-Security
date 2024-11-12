package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N23RefactoringSessionScanningTransferredFileColumn extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "3.2";
   }

   @Override
   public String getDescription() {
      return "Modify column 'kavosh_request_identifier' to accept null values";
   }

   @Override
   public String getScriptName() {
      return "23.refactor_session_scanning_transferred_file_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
