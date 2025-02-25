package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N18CreatingRdpConnectionRemoteApplicationTable extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.7";
   }

   @Override
   public String getDescription() {
      return "Creating table `tb_rdp_connection_remote_application` removing remote-app related columns from `tb_rdp_connection`";
   }

   @Override
   public String getScriptName() {
      return "18.rdp_remote_apps_table";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
