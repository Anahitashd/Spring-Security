package ir.fidar.pam.service;

import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.bridge.BridgeCreateDto;
import ir.fidar.pam.domain.dto.bridge.BridgeUpdateDto;

public interface BridgeCrudService extends CrudService<String, BridgeCreateDto, BridgeUpdateDto> {
}
