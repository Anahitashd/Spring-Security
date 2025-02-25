package ir.fidar.pam.domain.dto.connectiogroup;

import ir.fidar.core.domain.dto.crud.AbstractDescriptiveCreateDto;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import java.util.List;
import javax.validation.constraints.Size;

public class ConnectionGroupCreateDto extends AbstractDescriptiveCreateDto {
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   private List<String> connections;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public List<String> getConnections() {
      return this.connections;
   }

   public void setConnections(List<String> connections) {
      this.connections = connections;
   }
}
