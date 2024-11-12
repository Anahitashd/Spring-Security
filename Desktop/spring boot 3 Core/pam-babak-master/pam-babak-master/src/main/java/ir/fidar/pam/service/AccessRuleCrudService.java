package ir.fidar.pam.service;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.InfoDto;
import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.SessionDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleConditionInfoDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleCreateDto;
import ir.fidar.pam.domain.dto.accessrule.AccessRuleUpdateDto;
import ir.fidar.pam.exception.accessrule.AccessRuleDisabledException;
import ir.fidar.pam.exception.accessrule.AccessRuleExpiredException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.data.domain.Pageable;

public interface AccessRuleCrudService extends CrudService<String, AccessRuleCreateDto, AccessRuleUpdateDto> {
   Optional<CustomPageDto<SessionDto>> loadSessionsOfCurrentUser(Pageable var1, Sorting var2, String var3, Set<String> var4);

   Optional<AccessRuleConditionInfoDto> loadConditionInfo(String var1) throws InsufficientPrivilegeToAccessSessionException, AccessRuleDisabledException, AccessRuleExpiredException;

   Optional<List<InfoDto>> loadAccessRulesAssignedToSpecificUser(String var1);

   Optional<List<InfoDto>> loadAccessRulesAssignedToSpecificUserGroup(String var1);

   Optional<List<InfoDto>> loadAccessRulesSetOverSpecificConnection(String var1);

   Optional<List<InfoDto>> loadAccessRulesSetOverSpecificConnectionGroup(String var1);
}
