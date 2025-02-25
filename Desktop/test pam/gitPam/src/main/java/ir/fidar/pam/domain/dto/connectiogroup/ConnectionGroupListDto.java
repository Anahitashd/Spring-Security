package ir.fidar.pam.domain.dto.connectiogroup;

import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;

public class ConnectionGroupListDto extends FullAuditionReadDto {
   private String name;
   private int numberOfConnections;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public int getNumberOfConnections() {
      return this.numberOfConnections;
   }

   public void setNumberOfConnections(int numberOfConnections) {
      this.numberOfConnections = numberOfConnections;
   }
}
