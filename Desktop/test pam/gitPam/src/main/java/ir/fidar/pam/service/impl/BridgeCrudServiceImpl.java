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
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.license.register.LicenseInterceptingPoint;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.BridgeRepository;
import ir.fidar.pam.domain.dto.bridge.BridgeCreateDto;
import ir.fidar.pam.domain.dto.bridge.BridgeDetailsDto;
import ir.fidar.pam.domain.dto.bridge.BridgeListDto;
import ir.fidar.pam.domain.dto.bridge.BridgeUpdateDto;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.exception.BridgeNameAlreadyExistsException;
import ir.fidar.pam.exception.DeleteBridgeUsedByAccessRuleException;
import ir.fidar.pam.service.BridgeCrudService;
import java.util.List;
import java.util.Optional;
import javax.persistence.Tuple;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class BridgeCrudServiceImpl extends GlobalCommonServiceImpl<Bridge> implements BridgeCrudService {
   private final BridgeRepository bridgeRepository;

   public BridgeCrudServiceImpl(BridgeRepository bridgeRepository) {
      super(bridgeRepository);
      this.bridgeRepository = bridgeRepository;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      NativeQuery bridgeListQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("b", "b.name", "b.ip_address", "b.port"))
         .from(Bridge.class, "b")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> bridgeListDtoList = this.nativeQueryBasedReadRepository.findAll(bridgeListQuery, this::convertTupleToBridgeListDto);
      return Optional.of(bridgeListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) {
      NativePaginationQuery bridgeListQueryByPagination = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(QueryAndFilterUtils.appendFullAuditionColumns("b", "b.name", "b.ip_address", "b.port"))
         .from(Bridge.class, "b")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> bridgeListDtoListPage = this.nativeQueryBasedReadRepository.find(bridgeListQueryByPagination, this::convertTupleToBridgeListDto);
      return Optional.of(bridgeListDtoListPage);
   }

   public Optional<DetailsDto> load(String name) {
      Bridge bridge = Optional.ofNullable(this.bridgeRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Bridge.class)));
      BridgeDetailsDto bridgeDetailsDto = new BridgeDetailsDto();
      bridgeDetailsDto.setName(bridge.getName());
      bridgeDetailsDto.setIpAddress(bridge.getIpAddress());
      bridgeDetailsDto.setPort(bridge.getPort());
      bridgeDetailsDto.setRdpVirtualDriveStoragePath(bridge.getRdpVirtualDriveStoragePath());
      bridgeDetailsDto.setRecordsStoragePath(bridge.getRecordsStoragePath());
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)bridge, (AbstractDescriptiveDto)bridgeDetailsDto);
      return Optional.of(bridgeDetailsDto);
   }

   @LicenseInterceptingPoint
   public void create(BridgeCreateDto bridgeCreateDto) throws Exception {
      if (this.existsByName(bridgeCreateDto.getName())) {
         throw new ResourceAlreadyExistsException(new BridgeNameAlreadyExistsException());
      } else {
         Bridge bridge = new Bridge();
         bridge.setName(bridgeCreateDto.getName());
         bridge.setIpAddress(bridgeCreateDto.getIpAddress());
         bridge.setPort(bridgeCreateDto.getPort());
         bridge.setRdpVirtualDriveStoragePath(bridgeCreateDto.getRdpVirtualDriveStoragePath());
         bridge.setRecordsStoragePath(bridgeCreateDto.getRecordsStoragePath());
         bridge.setDescription(bridgeCreateDto.getDescription());
         this.bridgeRepository.save(bridge);
      }
   }

   public void update(String name, BridgeUpdateDto bridgeUpdateDto) throws Exception {
      RepositoryContextManager.startNewTransaction();

      try {
         Bridge bridge = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchBridgeByNameQuery(name), false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Bridge.class)));
         if (!bridgeUpdateDto.getName().equalsIgnoreCase(bridge.getName()) && this.existsByName(bridgeUpdateDto.getName())) {
            throw new ResourceAlreadyExistsException(new BridgeNameAlreadyExistsException());
         } else {
            bridge.setName(bridgeUpdateDto.getName());
            bridge.setIpAddress(bridgeUpdateDto.getIpAddress());
            bridge.setPort(bridgeUpdateDto.getPort());
            bridge.setRdpVirtualDriveStoragePath(bridgeUpdateDto.getRdpVirtualDriveStoragePath());
            bridge.setRecordsStoragePath(bridgeUpdateDto.getRecordsStoragePath());
            bridge.setDescription(bridgeUpdateDto.getDescription());
            this.crudRepository.update(bridge);
            RepositoryContextManager.commit();
         }
      } catch (Exception var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   public void delete(String name) throws Exception {
      RepositoryContextManager.startNewTransaction();

      try {
         Bridge bridge = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.fetchBridgeByNameQuery(name), false))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Bridge.class)));
         NativeQuery checkUsageByAnyAccessRuleQuery = new NativeQueryBuilder()
            .select("ar.name")
            .from(Bridge.class, "b")
            .join(AccessRule.class, "ar")
            .on("id", "bridge_id")
            .where(new FilterChainBuilder().filter(new FilterBuilder().string("name").eq(name).buildSingle()).build())
            .build();
         List<String> accessRuleNamesUsingThisBridge = this.nativeQueryBasedReadRepository
            .findAll(checkUsageByAnyAccessRuleQuery, tuple -> (String)tuple.get("name"));
         if (!accessRuleNamesUsingThisBridge.isEmpty()) {
            throw new DeleteBridgeUsedByAccessRuleException(accessRuleNamesUsingThisBridge);
         } else {
            this.crudRepository.remove(bridge);
            RepositoryContextManager.commit();
         }
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }
   }

   private boolean existsByName(String name) {
      return this.nativeQueryBasedReadRepository.exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(Bridge.class, "name", name));
   }

   private JpaQuery<Bridge> fetchBridgeByNameQuery(String name) {
      return new JpaQueryBuilder().from(Bridge.class, "b").where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name)).build();
   }

   private BridgeListDto convertTupleToBridgeListDto(Tuple tuple) {
      BridgeListDto bridgeListDto = new BridgeListDto();
      bridgeListDto.setIpAddress((String)tuple.get("ip_address"));
      bridgeListDto.setPort(new Long(tuple.get("port").toString()).intValue());
      bridgeListDto.setName((String)tuple.get("name"));
      AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)bridgeListDto);
      return bridgeListDto;
   }
}
