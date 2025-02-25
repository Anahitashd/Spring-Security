package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N11CreatingCaptureClientInformationTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.0";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_capture_client_information` which stores remote sessions client information";
   }

   @Override
   public String getScriptName() {
      return "11.creating_client_information_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
