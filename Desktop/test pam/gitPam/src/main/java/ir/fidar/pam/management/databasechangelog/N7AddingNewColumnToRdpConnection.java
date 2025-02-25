package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N7AddingNewColumnToRdpConnection extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.6";
   }

   @Override
   public String getDescription() {
      return "Adding new column 'printer_name' to `tb_rdp_connection` table";
   }

   @Override
   public String getScriptName() {
      return "7.add_new_column_to_rdp_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
