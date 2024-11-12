package ir.fidar.pam.service.connection;

import ir.fidar.core.service.generic.GenericService;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupInfoDto;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import java.util.Collection;
import java.util.Set;

public interface ConnectionGroupService extends GenericService<ConnectionGroup, String> {
   ConnectionGroup getOneByNameWithAllConnections(String var1);

   ConnectionGroupInfoDto convertToInfoDto(ConnectionGroup var1);

   Set<ConnectionGroupInfoDto> convertToInfoDto(Collection<ConnectionGroup> var1);
}
