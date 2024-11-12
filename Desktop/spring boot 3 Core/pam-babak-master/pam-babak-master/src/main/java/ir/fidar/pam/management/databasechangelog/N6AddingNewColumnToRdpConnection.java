package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N6AddingNewColumnToRdpConnection extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.5";
   }

   @Override
   public String getDescription() {
      return "Adding new column 'enable_audio_input' to `tb_rdp_connection` table";
   }

   @Override
   public String getScriptName() {
      return "6.add_new_column_to_rdp_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
