package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.JpaQuery;
import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.JpaQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.AbstractDescriptiveDto;
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.FullAuditionReadDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.model.DescriptiveBaseEntity;
import ir.fidar.core.domain.util.AuditionInfoAndGlobalFieldsCopier;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.generic.ResourceAlreadyExistsException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintCreateDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintDetailsDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintListDto;
import ir.fidar.pam.domain.dto.sessioninputconstraint.SessionInputConstraintUpdateDto;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.exception.sessioninputconstraint.DeleteInUseSessionInputConstraintException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintNameAlreadyExistsException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintRegexAlreadyExistsException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintRegexInvalidException;
import ir.fidar.pam.service.SessionInputConstraintCrudService;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.persistence.Tuple;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class SessionInputConstraintCrudServiceImpl extends GlobalCommonServiceImpl<SessionInputConstraint> implements SessionInputConstraintCrudService {
   private final SessionInputConstraintRepository sessionInputConstraintRepository;
   private final GenericCrudRepository<SessionInputConstraint> sessionInputConstraintcrudRepository;

   public SessionInputConstraintCrudServiceImpl(
      SessionInputConstraintRepository sessionInputConstraintRepository, GenericCrudRepository<SessionInputConstraint> sessionInputConstraintcrudRepository
   ) {
      super(sessionInputConstraintRepository);
      this.sessionInputConstraintRepository = sessionInputConstraintRepository;
      this.sessionInputConstraintcrudRepository = sessionInputConstraintcrudRepository;
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      NativeQuery sessionInputConstrainListQuery = new NativeQueryBuilder()
         .select(QueryAndFilterUtils.appendFullAuditionColumns("s", "s.name", "s.regex"))
         .from(SessionInputConstraint.class, "s")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      List<ListDto> sessionInputConstraintListDtoList = this.nativeQueryBasedReadRepository
         .findAll(sessionInputConstrainListQuery, this::convertTupleToSessionInputConstraintListDto);
      return Optional.of(sessionInputConstraintListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      NativePaginationQuery sessionInputConstrainListQuery = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(QueryAndFilterUtils.appendFullAuditionColumns("s", "s.name", "s.regex"))
         .from(SessionInputConstraint.class, "s")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> pageDto = this.nativeQueryBasedReadRepository
         .find(sessionInputConstrainListQuery, this::convertTupleToSessionInputConstraintListDto);
      return Optional.of(pageDto);
   }

   public Optional<DetailsDto> load(String name) {
      SessionInputConstraint sessionInputConstraint = Optional.ofNullable(this.sessionInputConstraintRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionInputConstraint.class)));
      SessionInputConstraintDetailsDto detailsDto = new SessionInputConstraintDetailsDto();
      detailsDto.setName(sessionInputConstraint.getName());
      detailsDto.setRegex(sessionInputConstraint.getRegex());
      AuditionInfoAndGlobalFieldsCopier.copy((DescriptiveBaseEntity)sessionInputConstraint, (AbstractDescriptiveDto)detailsDto);
      return Optional.of(detailsDto);
   }

   public void create(SessionInputConstraintCreateDto sessionInputConstraintCreateDto) throws Exception {
      if (existsByName(sessionInputConstraintCreateDto.getName()))
         throw new ResourceAlreadyExistsException(new SessionInputConstraintNameAlreadyExistsException());
      if (existsByRegex(sessionInputConstraintCreateDto.getRegex()))
         throw new ResourceAlreadyExistsException(new SessionInputConstraintRegexAlreadyExistsException());
      validateRegex(sessionInputConstraintCreateDto.getRegex());
      SessionInputConstraint sessionInputConstraint = new SessionInputConstraint();
      sessionInputConstraint.setName(sessionInputConstraintCreateDto.getName());
      sessionInputConstraint.setRegex(sessionInputConstraintCreateDto.getRegex());
      sessionInputConstraint.setDescription(sessionInputConstraintCreateDto.getDescription());
      this.sessionInputConstraintRepository.save(sessionInputConstraint);
   }

   public void update(String name, SessionInputConstraintUpdateDto sessionInputConstraintUpdateDto) throws Exception {
      RepositoryContextManager.startNewTransaction();

      try {
         SessionInputConstraint sessionInputConstraint = Optional.ofNullable(
               this.jpaQueryBasedReadRepository.findOne(this.fetchSessionInputConstraintByNameQuery(name), false)
            )
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionInputConstraint.class)));
         if (!sessionInputConstraintUpdateDto.getName().equalsIgnoreCase(sessionInputConstraint.getName())
            && this.existsByName(sessionInputConstraintUpdateDto.getName())) {
            throw new ResourceAlreadyExistsException(new SessionInputConstraintNameAlreadyExistsException());
         } else if (!sessionInputConstraintUpdateDto.getRegex().equals(sessionInputConstraint.getRegex())
            && this.existsByRegex(sessionInputConstraintUpdateDto.getRegex())) {
            throw new SessionInputConstraintRegexAlreadyExistsException();
         } else {
            this.validateRegex(sessionInputConstraintUpdateDto.getRegex());
            sessionInputConstraint.setName(sessionInputConstraintUpdateDto.getName());
            sessionInputConstraint.setRegex(sessionInputConstraintUpdateDto.getRegex());
            sessionInputConstraint.setDescription(sessionInputConstraintUpdateDto.getDescription());
            this.crudRepository.update(sessionInputConstraint);
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
         SessionInputConstraint sessionInputConstraint = Optional.ofNullable(
               this.jpaQueryBasedReadRepository.findOne(this.fetchSessionInputConstraintByNameQuery(name))
            )
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionInputConstraint.class)));
         NativeQuery constraintViolationHandlerExistQuery = new NativeQueryBuilder()
            .checkExistence()
            .from(SessionInputConstraintViolationHandler.class, "s")
            .join(SessionInputConstraint.class, "sic")
            .on("constraint_id", "id")
            .joinWhere(new FilterChainBuilder().filter(new FilterBuilder().string("regex").eq(sessionInputConstraint.getRegex()).buildSingle()).build())
            .build();
         if (this.nativeQueryBasedReadRepository.exists(constraintViolationHandlerExistQuery)) {
            throw new DeleteInUseSessionInputConstraintException();
         } else {
            this.crudRepository.remove(sessionInputConstraint);
            RepositoryContextManager.commit();
         }
      } catch (Exception var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   private boolean existsByName(String name) {
      return this.nativeQueryBasedReadRepository
         .exists(QueryAndFilterUtils.createExistsQueryOnCaseInsensitiveStringColumn(SessionInputConstraint.class, "name", name));
   }

   private boolean existsByRegex(String regex) {
      return this.nativeQueryBasedReadRepository
         .exists(QueryAndFilterUtils.createExistsQueryOnCaseSensitiveStringColumn(SessionInputConstraint.class, "regex", regex));
   }

   private JpaQuery<SessionInputConstraint> fetchSessionInputConstraintByNameQuery(String name) {
      return new JpaQueryBuilder().from(SessionInputConstraint.class, "s").where(QueryAndFilterUtils.caseInsensitiveStringFilter("name", name)).build();
   }

   private SessionInputConstraintListDto convertTupleToSessionInputConstraintListDto(Tuple tuple) {
      SessionInputConstraintListDto sessionInputConstraintListDto = new SessionInputConstraintListDto();
      sessionInputConstraintListDto.setName((String)tuple.get("name"));
      sessionInputConstraintListDto.setRegex((String)tuple.get("regex"));
      AuditionInfoAndGlobalFieldsCopier.copy(tuple, (FullAuditionReadDto)sessionInputConstraintListDto);
      return sessionInputConstraintListDto;
   }

   private void validateRegex(String regex) throws SessionInputConstraintRegexInvalidException {
      try {
         Pattern.compile(regex);
      } catch (PatternSyntaxException var3) {
         throw new SessionInputConstraintRegexInvalidException();
      }
   }
}
