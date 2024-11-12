package ir.fidar.pam.domain.dto.connectiogroup;

import ir.fidar.core.domain.dto.crud.FullAuditionDescriptiveDetailsDto;
import ir.fidar.pam.domain.dto.connection.ConnectionInfoDto;
import java.util.List;

public class ConnectionGroupDetailsDto extends FullAuditionDescriptiveDetailsDto {
   private String name;
   private List<ConnectionInfoDto> connections;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public List<ConnectionInfoDto> getConnections() {
      return this.connections;
   }

   public void setConnections(List<ConnectionInfoDto> connections) {
      this.connections = connections;
   }
}
