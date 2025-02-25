package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.dto.management.user.UserInfoDto;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.service.management.user.UserService;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.FilterChain;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.ResourceAccessInfoRepository;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoCreateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoDetailsDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoListDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.ResourceAccessInfoUpdateDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.SharedResourceAccessInfoListDto;
import ir.fidar.pam.domain.dto.resourceaccessinfo.SharedResourceAccessInfoUpdateDto;
import ir.fidar.pam.domain.model.ResourceAccessInfo;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.exception.resourceaccessinfo.ResourceAccessInfoLabelAlreadyExistsException;
import ir.fidar.pam.exception.resourceaccessinfo.ResourceAccessInfoNoInfoProvidedException;
import ir.fidar.pam.exception.resourceaccessinfo.UnprivilegedSharedResourceAccessInfoEditionException;
import ir.fidar.pam.service.ResourceAccessInfoCrudService;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.persistence.Tuple;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ResourceAccessInfoCrudServiceImpl extends GlobalCommonServiceImpl<ResourceAccessInfo> implements ResourceAccessInfoCrudService {
   private static final String[] LIST_DTO_COLUMNS = new String[]{"rai.label", "rai.username", "rai.password", "rai.secretKey", "rai.editSharedInfoPrivileged"};
   private static final String[] SHARED_RESOURCES_LIST_DTO_COLUMNS = new String[]{
      "rai.label", "rai.username", "rai.password", "rai.secretKey", "rai.editSharedInfoPrivileged", "rai.creator"
   };
   private final UserService userService;

   public ResourceAccessInfoCrudServiceImpl(ResourceAccessInfoRepository resourceAccessInfoRepository, UserService userService) {
      super(resourceAccessInfoRepository);
      this.userService = userService;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      filters.add(new FilterBuilder().string("creator").eq(this.getCurrentUserUsername()).ignoreCaseSensitive().buildSingle());
      NativeQuery<ResourceAccessInfo> accessRuleInfoDtoNativeQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("rai", LIST_DTO_COLUMNS))
         .from(ResourceAccessInfo.class, "rai")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> resourceAccessInfoList = this.nativeQueryBasedReadRepository
         .findAll(accessRuleInfoDtoNativeQuery, this::convertTupleToResourceAccessInfoListDto);
      return Optional.of(resourceAccessInfoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      filters.add(new FilterBuilder().string("creator").eq(this.getCurrentUserUsername()).ignoreCaseSensitive().buildSingle());
      NativePaginationQuery<ResourceAccessInfo> accessRuleInfoDtoNativeQuery = (NativePaginationQuery<ResourceAccessInfo>)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(QueryAndFilterUtils.appendFullAuditionColumns("rai", LIST_DTO_COLUMNS))
         .from(ResourceAccessInfo.class, "rai")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> resourceAccessInfoPage = this.nativeQueryBasedReadRepository
         .find(accessRuleInfoDtoNativeQuery, this::convertTupleToResourceAccessInfoListDto);
      return Optional.of(resourceAccessInfoPage);
   }

   public Optional<DetailsDto> load(String label) {
      ResourceAccessInfo resourceAccessInfo = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchResourceAccessInfoByLabelWithSharingUsers(label))
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ResourceAccessInfo.class)));
      ResourceAccessInfoDetailsDto resourceAccessInfoDetailsDto = new ResourceAccessInfoDetailsDto();
      resourceAccessInfoDetailsDto.setLabel(resourceAccessInfo.getLabel());
      resourceAccessInfoDetailsDto.setUsername(resourceAccessInfo.getUsername());
      resourceAccessInfoDetailsDto.setPassword(resourceAccessInfo.getPassword());
      resourceAccessInfoDetailsDto.setSecretKey(resourceAccessInfo.getSecretKey());
      resourceAccessInfoDetailsDto.setEditSharedInfoPrivileged(resourceAccessInfo.isEditSharedInfoPrivileged());
      if (!resourceAccessInfo.getUsersToShare().isEmpty()) {
         Set<UserInfoDto> userInfoDtoSet = new HashSet<>();

         for (User user : resourceAccessInfo.getUsersToShare()) {
            UserInfoDto userInfoDto = new UserInfoDto();
            userInfoDto.setUsername(user.getUsername());
            userInfoDtoSet.add(userInfoDto);
         }

         resourceAccessInfoDetailsDto.setUsersToShare(userInfoDtoSet);
      }

      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)resourceAccessInfo, (AbstractDescriptiveDto)resourceAccessInfoDetailsDto);
      return Optional.of(resourceAccessInfoDetailsDto);
   }

   public void create(ResourceAccessInfoCreateDto resourceAccessInfoCreateDto) throws Exception {
      if (this.existResourceInfoByLabelAndOwner(resourceAccessInfoCreateDto.getLabel())) {
         throw new ResourceAlreadyExistsException(new ResourceAccessInfoLabelAlreadyExistsException());
      } else {
         this.checkIfInfoIsProvided(resourceAccessInfoCreateDto);
         RepositoryContextManager.startNewTransaction();

         try {
            ResourceAccessInfo resourceAccessInfo = new ResourceAccessInfo();
            this.convertResourceAccessInfoCreateDtoToResourceAccessInfo(resourceAccessInfo, resourceAccessInfoCreateDto);
            Set<String> usersToShare = resourceAccessInfoCreateDto.getUsersToShare();
            if (this.authorizationService.hasDesPrivilege("USER:READ") && usersToShare != null && !usersToShare.isEmpty()) {
               for (String userUsername : usersToShare) {
                  resourceAccessInfo.addUserToShare((User)this.userService.getOne(userUsername));
               }

               resourceAccessInfo.setEditSharedInfoPrivileged(resourceAccessInfoCreateDto.isEditSharedInfoPrivileged());
            }

            this.crudRepository.save(resourceAccessInfo);
            RepositoryContextManager.commit();
         } catch (Exception var6) {
            RepositoryContextManager.rollback();
            throw var6;
         }
      }
   }

   public void update(String label, ResourceAccessInfoUpdateDto resourceAccessInfoUpdateDto) throws Exception {
      ResourceAccessInfo resourceAccessInfo = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchResourceAccessInfoByLabelWithSharingUsers(label), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ResourceAccessInfo.class)));
      if (!resourceAccessInfo.getLabel().equals(resourceAccessInfoUpdateDto.getLabel())
         && this.existResourceInfoByLabelAndOwner(resourceAccessInfoUpdateDto.getLabel())) {
         throw new ResourceAlreadyExistsException(new ResourceAccessInfoLabelAlreadyExistsException());
      } else {
         this.checkIfInfoIsProvided(resourceAccessInfoUpdateDto);
         RepositoryContextManager.startNewTransaction();

         try {
            this.convertResourceAccessInfoCreateDtoToResourceAccessInfo(resourceAccessInfo, resourceAccessInfoUpdateDto);
            Set<String> usersToShare = resourceAccessInfoUpdateDto.getUsersToShare();
            if (this.authorizationService.hasDesPrivilege("USER:READ") && usersToShare != null && !usersToShare.isEmpty()) {
               Set<User> oldUsersToShare = resourceAccessInfo.getUsersToShare();
               Set<User> newUsersToShare = new HashSet<>();

               for (String userUsername : usersToShare) {
                  newUsersToShare.add((User)this.userService.getOne(userUsername));
               }

               Set<User> temp = new HashSet<>(oldUsersToShare);
               temp.removeAll(newUsersToShare);
               temp.forEach(resourceAccessInfo::removeUserToShare);
               temp.clear();
               temp.addAll(newUsersToShare);
               temp.removeAll(oldUsersToShare);
               temp.forEach(resourceAccessInfo::addUserToShare);
               resourceAccessInfo.setEditSharedInfoPrivileged(resourceAccessInfoUpdateDto.isEditSharedInfoPrivileged());
            } else {
               resourceAccessInfo.getUsersToShare().clear();
               resourceAccessInfo.setEditSharedInfoPrivileged(false);
            }

            this.crudRepository.update(resourceAccessInfo);
            RepositoryContextManager.commit();
         } catch (Exception var9) {
            RepositoryContextManager.rollback();
            throw var9;
         }
      }
   }

   public void delete(String label) throws Exception {
      JpaQuery<ResourceAccessInfo> query = new JpaQueryBuilder()
         .from(ResourceAccessInfo.class, "rai")
         .where(this.generateFilterOnLabelAndOwner(label, this.getCurrentUserUsername()))
         .build();
      ResourceAccessInfo resourceAccessInfo = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(query, false))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ResourceAccessInfo.class)));
      RepositoryContextManager.startNewTransaction();

      try {
         this.crudRepository.remove(resourceAccessInfo);
         RepositoryContextManager.commit();
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }
   }

   @Override
   public Optional<List<SharedResourceAccessInfoListDto>> loadSharedResources(List<LinkedFilter> filters, Sorting sorting) {
      filters = filters.stream().peek(filter -> {
         if (filter.getFilter().getProperty().equalsIgnoreCase("owner")) {
            filter.getFilter().setProperty("creator");
         }
      }).collect(Collectors.toList());
      if (sorting.getProperty().equals("id")) {
         sorting = new Sorting("rai.id", sorting.getOrder());
      }

      NativeQuery<ResourceAccessInfo> sharedResourcesQuery = new NativeQueryBuilder()
         .select(SHARED_RESOURCES_LIST_DTO_COLUMNS)
         .from(ResourceAccessInfo.class, "rai")
         .joinM2M(User.class, "u")
         .joinWhere(QueryAndFilterUtils.foreignKeyFilter("id", this.authorizationService.getCurrentUserInfo().getId()))
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<SharedResourceAccessInfoListDto> sharedResourceAccessInfoListDtoList = this.nativeQueryBasedReadRepository
         .findAll(sharedResourcesQuery, this::convertTupleToSharedResourceAccessInfoListDto);
      return Optional.of(sharedResourceAccessInfoListDtoList);
   }

   @Override
   public Optional<CustomPageDto<SharedResourceAccessInfoListDto>> loadSharedResources(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) {
      filters = filters.stream().peek(filter -> {
         if (filter.getFilter().getProperty().equalsIgnoreCase("owner")) {
            filter.getFilter().setProperty("creator");
         }
      }).collect(Collectors.toList());
      if (sorting.getProperty().equals("id")) {
         sorting = new Sorting("rai.id", sorting.getOrder());
      }

      NativePaginationQuery<ResourceAccessInfo> sharedResourcesQuery = (NativePaginationQuery<ResourceAccessInfo>)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(SHARED_RESOURCES_LIST_DTO_COLUMNS)
         .from(ResourceAccessInfo.class, "rai")
         .joinM2M(User.class, "u")
         .joinWhere(QueryAndFilterUtils.foreignKeyFilter("id", this.authorizationService.getCurrentUserInfo().getId()))
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<SharedResourceAccessInfoListDto> sharedResourceAccessInfoListPage = this.nativeQueryBasedReadRepository
         .find(sharedResourcesQuery, this::convertTupleToSharedResourceAccessInfoListDto);
      return Optional.of(sharedResourceAccessInfoListPage);
   }

   @Override
   public void updateSharedResource(SharedResourceAccessInfoUpdateDto sharedResourceAccessInfoUpdateDto) throws UnprivilegedSharedResourceAccessInfoEditionException, ResourceAccessInfoNoInfoProvidedException {
      Long currentUserId = this.authorizationService.getCurrentUserInfo().getId();
      String username = sharedResourceAccessInfoUpdateDto.getUsername();
      String password = sharedResourceAccessInfoUpdateDto.getPassword();
      String key = sharedResourceAccessInfoUpdateDto.getSecretKey();
      if (!StringUtils.hasContent(username) && !StringUtils.hasContent(password) && !StringUtils.hasContent(key)) {
         throw new ResourceAccessInfoNoInfoProvidedException();
      } else {
         JpaQuery<ResourceAccessInfo> fetchRecordQuery = new JpaQueryBuilder()
            .from(ResourceAccessInfo.class, "rai")
            .join("usersToShare", "uts")
            .on(QueryAndFilterUtils.idFilter(currentUserId))
            .where(this.generateFilterOnLabelAndOwner(sharedResourceAccessInfoUpdateDto.getLabel(), sharedResourceAccessInfoUpdateDto.getOwner()))
            .build();
         RepositoryContextManager.startNewTransaction();

         try {
            ResourceAccessInfo resourceAccessInfo = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(fetchRecordQuery, false))
               .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ResourceAccessInfo.class)));
            if (!resourceAccessInfo.isEditSharedInfoPrivileged()) {
               throw new UnprivilegedSharedResourceAccessInfoEditionException();
            } else {
               resourceAccessInfo.setUsername(username);
               resourceAccessInfo.setPassword(password);
               resourceAccessInfo.setSecretKey(key);
               this.crudRepository.save(resourceAccessInfo);
               RepositoryContextManager.commit();
            }
         } catch (Exception var8) {
            RepositoryContextManager.rollback();
            throw var8;
         }
      }
   }

   private void checkIfInfoIsProvided(ResourceAccessInfoCreateDto resourceAccessInfoCreateDto) throws ResourceAccessInfoNoInfoProvidedException {
      if (!StringUtils.hasContent(resourceAccessInfoCreateDto.getUsername())
         && !StringUtils.hasContent(resourceAccessInfoCreateDto.getPassword())
         && !StringUtils.hasContent(resourceAccessInfoCreateDto.getSecretKey())) {
         throw new ResourceAccessInfoNoInfoProvidedException();
      }
   }

   private String getCurrentUserUsername() {
      return this.authorizationService.getCurrentUserInfo().getUsername();
   }

   private List<FilterChain> generateFilterOnLabelAndOwner(String label, String owner) {
      return new FilterChainBuilder()
         .filter(new FilterBuilder().string("label").eq(label).ignoreCaseSensitive().and().string("creator").eq(owner).ignoreCaseSensitive().build())
         .build();
   }

   private ResourceAccessInfoListDto convertTupleToResourceAccessInfoListDto(Tuple tuple) {
      ResourceAccessInfoListDto resourceAccessInfoListDto = new ResourceAccessInfoListDto();
      resourceAccessInfoListDto.setLabel((String)tuple.get("label", String.class));
      resourceAccessInfoListDto.setUsername((String)tuple.get("username", String.class));
      resourceAccessInfoListDto.setPassword((String)tuple.get("password", String.class));
      resourceAccessInfoListDto.setSecretKey((String)tuple.get("secretKey", String.class));
      resourceAccessInfoListDto.setEditSharedInfoPrivileged((Boolean)tuple.get("editSharedInfoPrivileged", Boolean.class));
      AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)resourceAccessInfoListDto);
      return resourceAccessInfoListDto;
   }

   private void setCommonFields(Tuple tuple, ResourceAccessInfoListDto resourceAccessInfoListDto) {
   }

   private boolean existResourceInfoByLabelAndOwner(String label) {
      return this.nativeQueryBasedReadRepository
         .exists(
            new NativeQueryBuilder()
               .checkExistence()
               .from(ResourceAccessInfo.class, "rai")
               .where(this.generateFilterOnLabelAndOwner(label, this.getCurrentUserUsername()))
               .build()
         );
   }

   private JpaQuery<ResourceAccessInfo> fetchResourceAccessInfoByLabelWithSharingUsers(String label) {
      return new JpaQueryBuilder()
         .from(ResourceAccessInfo.class, "rai")
         .leftJoin("usersToShare", "uts")
         .where(this.generateFilterOnLabelAndOwner(label, this.getCurrentUserUsername()))
         .build();
   }

   private void convertResourceAccessInfoCreateDtoToResourceAccessInfo(
      ResourceAccessInfo resourceAccessInfo, ResourceAccessInfoCreateDto resourceAccessInfoCreateDto
   ) throws ResourceAccessInfoNoInfoProvidedException {
      resourceAccessInfo.setLabel(resourceAccessInfoCreateDto.getLabel());
      resourceAccessInfo.setUsername(resourceAccessInfoCreateDto.getUsername());
      resourceAccessInfo.setPassword(resourceAccessInfoCreateDto.getPassword());
      resourceAccessInfo.setSecretKey(resourceAccessInfoCreateDto.getSecretKey());
      resourceAccessInfo.setDescription(resourceAccessInfoCreateDto.getDescription());
   }

   private SharedResourceAccessInfoListDto convertTupleToSharedResourceAccessInfoListDto(Tuple tuple) {
      SharedResourceAccessInfoListDto sharedResourceAccessInfoListDto = new SharedResourceAccessInfoListDto();
      sharedResourceAccessInfoListDto.setLabel((String)tuple.get("label", String.class));
      sharedResourceAccessInfoListDto.setUsername((String)tuple.get("username", String.class));
      sharedResourceAccessInfoListDto.setPassword((String)tuple.get("password", String.class));
      sharedResourceAccessInfoListDto.setSecretKey((String)tuple.get("secretKey", String.class));
      sharedResourceAccessInfoListDto.setEditSharedInfoPrivileged((Boolean)tuple.get("editSharedInfoPrivileged", Boolean.class));
      sharedResourceAccessInfoListDto.setOwner((String)tuple.get("creator", String.class));
      return sharedResourceAccessInfoListDto;
   }
}
