package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N1Initialization extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.0";
   }

   @Override
   public String getDescription() {
      return "Initializing PAM specific tables";
   }

   @Override
   public String getScriptName() {
      return "1.pam_schema_initialization";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
