package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N9FixingVncConnection extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.8";
   }

   @Override
   public String getDescription() {
      return "Removing not null constraints from 'repeater_host' and 'repeater_port' columns";
   }

   @Override
   public String getScriptName() {
      return "9.fix_vnc_connection_constraints";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
