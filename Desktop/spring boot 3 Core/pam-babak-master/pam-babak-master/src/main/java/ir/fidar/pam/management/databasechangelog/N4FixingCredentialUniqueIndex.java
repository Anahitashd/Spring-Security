package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N4FixingCredentialUniqueIndex extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.3";
   }

   @Override
   public String getDescription() {
      return "Create unique constraint over 'label' and 'connection_id'";
   }

   @Override
   public String getScriptName() {
      return "4.fixing_credential_unique_index";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
