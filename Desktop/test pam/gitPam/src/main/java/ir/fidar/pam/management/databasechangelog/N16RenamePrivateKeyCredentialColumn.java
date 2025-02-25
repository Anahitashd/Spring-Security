package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N16RenamePrivateKeyCredentialColumn extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "2.5";
   }

   @Override
   public String getDescription() {
      return "Rename 'private_kay' column to 'private_key'";
   }

   @Override
   public String getScriptName() {
      return "16.rename_private_key_cred_column";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
