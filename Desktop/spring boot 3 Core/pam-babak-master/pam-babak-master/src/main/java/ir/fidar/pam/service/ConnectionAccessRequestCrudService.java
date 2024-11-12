package ir.fidar.pam.service;

import ir.fidar.core.service.generic.CrudService;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestCreateDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestReviewDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestUpdateDto;

public interface ConnectionAccessRequestCrudService extends CrudService<String, ConnectionAccessRequestCreateDto, ConnectionAccessRequestUpdateDto> {
   void reviewRequest(String var1, ConnectionAccessRequestReviewDto var2) throws Exception;
}
