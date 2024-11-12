package ir.fidar.pam.controller.management;

import ir.fidar.pam.domain.type.ConnectionType;

class MostActiveConnectionsDto {
   private String name;
   private ConnectionType type;
   private int count;

   public MostActiveConnectionsDto() {
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public ConnectionType getType() {
      return this.type;
   }

   public void setType(ConnectionType type) {
      this.type = type;
   }

   public int getCount() {
      return this.count;
   }

   public void setCount(int count) {
      this.count = count;
   }
}
