package ir.fidar.pam.service;

import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintCreateDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintUpdateDto;

public interface SessionInputConstraintCrudService extends CrudService<String, SessionInputConstraintCreateDto, SessionInputConstraintUpdateDto> {
}
