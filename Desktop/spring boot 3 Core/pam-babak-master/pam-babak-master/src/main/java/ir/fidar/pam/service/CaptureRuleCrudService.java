package ir.fidar.pam.service;

import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleCreateDto;
import ir.fidar.pam.domain.dto.capturerule.CaptureRuleUpdateDto;
import java.util.List;
import java.util.Optional;

public interface CaptureRuleCrudService extends CrudService<String, CaptureRuleCreateDto, CaptureRuleUpdateDto> {
   Optional<List<InfoDto>> loadCaptureRulesAssignedToSpecificUser(String var1);

   Optional<List<InfoDto>> loadCaptureRulesAssignedToSpecificUserGroup(String var1);

   Optional<List<InfoDto>> loadCaptureRulesSetOverSpecificConnection(String var1);

   Optional<List<InfoDto>> loadCaptureRulesSetOverSpecificConnectionGroup(String var1);
}
