package ir.fidar.pam.service;

import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.service.generic.CrudService;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoCreateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoUpdateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.SharedResourceAccessInfoListDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.SharedResourceAccessInfoUpdateDto;
import ir.fidar.pam.exception.resourceaccessinfo.ResourceAccessInfoNoInfoProvidedException;
import ir.fidar.pam.exception.resourceaccessinfo.UnprivilegedSharedResourceAccessInfoEditionException;
import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;

public interface ResourceAccessInfoCrudService extends CrudService<String, ResourceAccessInfoCreateDto, ResourceAccessInfoUpdateDto> {
   Optional<List<SharedResourceAccessInfoListDto>> loadSharedResources(List<LinkedFilter> var1, Sorting var2);

   Optional<CustomPageDto<SharedResourceAccessInfoListDto>> loadSharedResources(List<LinkedFilter> var1, Pageable var2, Sorting var3);

   void updateSharedResource(SharedResourceAccessInfoUpdateDto var1) throws UnprivilegedSharedResourceAccessInfoEditionException, ResourceAccessInfoNoInfoProvidedException;
}
