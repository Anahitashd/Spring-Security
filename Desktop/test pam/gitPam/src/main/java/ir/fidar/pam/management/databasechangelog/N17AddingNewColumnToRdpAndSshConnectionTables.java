package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N17AddingNewColumnToRdpAndSshConnectionTables extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.6";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_session_scanning_transferred_files` and adding new column 'malware_scanning_enabled' to 'tb_ssh_connection' and 'tb_rdp_connection'";
   }

   @Override
   public String getScriptName() {
      return "17.scanning_transferred_files_table_and_new_cols";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
