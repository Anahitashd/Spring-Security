package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N2RemovingLogIncidentField extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.1";
   }

   @Override
   public String getDescription() {
      return "Dropping 'log_incident' column";
   }

   @Override
   public String getScriptName() {
      return "2.removing_log_incident_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
