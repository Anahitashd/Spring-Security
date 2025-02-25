package ir.fidar.pam.service.connection;

import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupCreateDto;
import ir.fidar.pam.domain.dto.connectiogroup.ConnectionGroupUpdateDto;

public interface ConnectionGroupCrudService extends CrudService<String, ConnectionGroupCreateDto, ConnectionGroupUpdateDto> {
}
