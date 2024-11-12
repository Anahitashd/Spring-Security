package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N3FixingDomainCredential extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.2";
   }

   @Override
   public String getDescription() {
      return "Adding 'username' and 'password' columns";
   }

   @Override
   public String getScriptName() {
      return "3.fixing_domain_credential";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
