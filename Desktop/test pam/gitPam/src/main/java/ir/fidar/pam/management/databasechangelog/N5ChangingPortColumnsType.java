package ir.fidar.pam.management.databasechangelog;

import ir.fidar.core.management.database.migration.NoneCoreDatabaseMigration;

public class N5ChangingPortColumnsType extends NoneCoreDatabaseMigration {
   @Override
   public String getVersion() {
      return "1.4";
   }

   @Override
   public String getDescription() {
      return "Changing type of all `port` columns to `MEDIUMINT` due to hibernate bug";
   }

   @Override
   public String getScriptName() {
      return "5.changing_port_columns_type";
   }

   @Override
   public boolean applyAsOneStatement() {
      return false;
   }
}
