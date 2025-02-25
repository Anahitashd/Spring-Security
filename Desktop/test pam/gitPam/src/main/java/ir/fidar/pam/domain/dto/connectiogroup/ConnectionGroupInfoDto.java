package ir.fidar.pam.domain.dto.connectiogroup;

import ir.fidar.core.domain.dto.crud.InfoDto;

public class ConnectionGroupInfoDto implements InfoDto {
   private String name;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }
}
