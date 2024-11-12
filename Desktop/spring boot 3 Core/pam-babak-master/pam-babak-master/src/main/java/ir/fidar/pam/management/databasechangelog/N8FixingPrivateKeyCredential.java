package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N8FixingPrivateKeyCredential extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.7";
   }

   @Override
   public String getDescription() {
      return "Add `username` column to `tb_private_key_credential` table";
   }

   @Override
   public String getScriptName() {
      return "8.fix_private_key_credential";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
