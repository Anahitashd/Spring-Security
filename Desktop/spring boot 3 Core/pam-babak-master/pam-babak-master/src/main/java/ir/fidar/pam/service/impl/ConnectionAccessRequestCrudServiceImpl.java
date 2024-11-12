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
import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.domain.dto.management.notification.ServerEvent;
import ir.fidar.core.domain.dto.management.notification.ServerEventType;
import ir.fidar.core.domain.model.management.security.Role;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.SystemConstantsAndDefaults;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.management.email.EmailSender;
import ir.fidar.core.management.internationalization.MessageResolver;
import ir.fidar.core.management.sms.SmsSender;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.ConnectionAccessRequestRepository;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestCreateDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestDetailsDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestListDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestReviewDetailsDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestReviewDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestReviewListDto;
import ir.fidar.pam.domain.dto.connectionaccessrequest.ConnectionAccessRequestUpdateDto;
import ir.fidar.pam.domain.model.ConnectionAccessRequest;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.type.ConnectionAccessRequestStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.converter.attribbute.ConnectionAccessRequestStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.FileTransferModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.exception.connectionaccessrequest.AlreadyHasAccessToRequestedHostException;
import ir.fidar.pam.exception.connectionaccessrequest.ConnectionAccessRequestLockedException;
import ir.fidar.pam.exception.connectionaccessrequest.ConnectionAccessRequestOwnershipException;
import ir.fidar.pam.service.AccessRuleService;
import ir.fidar.pam.service.ConnectionAccessRequestCrudService;
import ir.fidar.pam.service.UserService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jakarta.persistence.Tuple;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class ConnectionAccessRequestCrudServiceImpl extends GlobalCommonServiceImpl<ConnectionAccessRequest> implements ConnectionAccessRequestCrudService {
   private static final String CONNECTION_NAME_FORMAT = "REQUESTED_%s_%s_%s";
   private static final String ACCESS_RULE_NAME_FORMAT = "%s_ACCESS_RULE";
   private static final String[] COLUMN_LIST = new String[]{
      "car.identifier", "car.applicationTime", "car.ipAddress", "car.port", "car.type", "car.clipboardEnabled", "car.fileTransferMode", "car.status"
   };
   private static final String[] ADMIN_COLUMN_LIST = Arrays.copyOf(COLUMN_LIST, COLUMN_LIST.length + 1);
   private final ConnectionAccessRequestRepository connectionAccessRequestRepository;
   private final NotificationService notificationService;
   private final EmailSender emailSender;
   private final SmsSender smsSender;
   private final MessageResolver messageResolver;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private final UserService userService;
   private final ConnectionService connectionService;
   private final AccessRuleService accessRuleService;
   private final ConnectionTypeConverter connectionTypeConverter;
   private final ConnectionAccessRequestStatusConverter connectionAccessRequestStatusConverter;
   private final FileTransferModeConverter fileTransferModeConverter;

   public ConnectionAccessRequestCrudServiceImpl(
      ConnectionAccessRequestRepository connectionAccessRequestRepository,
      NotificationService notificationService,
      EmailSender emailSender,
      SmsSender smsSender,
      MessageResolver messageResolver,
      AsyncTaskExecutor asyncTaskExecutor,
      UserService userService,
      ConnectionService connectionService,
      AccessRuleService accessRuleService
   ) {
      super(connectionAccessRequestRepository);
      this.connectionAccessRequestRepository = connectionAccessRequestRepository;
      this.notificationService = notificationService;
      this.emailSender = emailSender;
      this.smsSender = smsSender;
      this.messageResolver = messageResolver;
      this.asyncTaskExecutor = asyncTaskExecutor;
      this.userService = userService;
      this.connectionService = connectionService;
      this.accessRuleService = accessRuleService;
      this.connectionTypeConverter = new ConnectionTypeConverter();
      this.connectionAccessRequestStatusConverter = new ConnectionAccessRequestStatusConverter();
      this.fileTransferModeConverter = new FileTransferModeConverter();
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      List<LinkedFilter>[] processedFilters = this.processFilters(filters);
      this.fixSortingProperty(sorting);
      String[] columns;
      if (this.isAdminUser()) {
         columns = ADMIN_COLUMN_LIST;
      } else {
         this.addApplicantIdFilter(processedFilters[1]);
         columns = COLUMN_LIST;
      }

      NativeQuery fetchConnectionAccessRequestsQuery = new NativeQueryBuilder()
         .select(columns)
         .from(ConnectionAccessRequest.class, "car")
         .join(User.class, "u")
         .on("user_id", "id")
         .joinWhere(new FilterChainBuilder().filter(processedFilters[1]).build())
         .where(new FilterChainBuilder().filter(processedFilters[0]).build())
         .orderBy(sorting)
         .build();
      List<ListDto> connectionAccessRequestListDtoList = this.nativeQueryBasedReadRepository
         .findAll(
            fetchConnectionAccessRequestsQuery,
            this.isAdminUser() ? this::convertTupleToConnectionAccessRequestApprovalListDto : this::convertTupleToConnectionAccessRequestListDto
         );
      return Optional.of(connectionAccessRequestListDtoList);
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      List<LinkedFilter>[] processedFilters = this.processFilters(filters);
      this.fixSortingProperty(sorting);
      String[] columns;
      if (this.isAdminUser()) {
         columns = ADMIN_COLUMN_LIST;
      } else {
         this.addApplicantIdFilter(processedFilters[1]);
         columns = COLUMN_LIST;
      }

      NativePaginationQuery fetchConnectionAccessRequestsByPageQuery = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(pageable)
         .select(columns)
         .from(ConnectionAccessRequest.class, "car")
         .join(User.class, "u")
         .on("user_id", "id")
         .joinWhere(new FilterChainBuilder().filter(processedFilters[1]).build())
         .where(new FilterChainBuilder().filter(processedFilters[0]).build())
         .orderBy(sorting)
         .build();
      CustomPageDto<ListDto> connectionAccessRequestListDtoPage = this.nativeQueryBasedReadRepository
         .find(
            fetchConnectionAccessRequestsByPageQuery,
            this.isAdminUser() ? this::convertTupleToConnectionAccessRequestApprovalListDto : this::convertTupleToConnectionAccessRequestListDto
         );
      return Optional.of(connectionAccessRequestListDtoPage);
   }

   public Optional<DetailsDto> load(String identifier) {
      ConnectionAccessRequest connectionAccessRequest = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionAccessRequestWithUserByIdentifier(identifier))
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionAccessRequest.class)));
      DetailsDto detailsDto;
      if (this.isAdminUser()) {
         ConnectionAccessRequestReviewDetailsDto connectionAccessRequestReviewDetailsDto = new ConnectionAccessRequestReviewDetailsDto();
         this.copyCommonFields(connectionAccessRequest, connectionAccessRequestReviewDetailsDto);
         connectionAccessRequestReviewDetailsDto.setApplicant(connectionAccessRequest.getUser().getUsername());
         detailsDto = connectionAccessRequestReviewDetailsDto;
      } else {
         ConnectionAccessRequestDetailsDto connectionAccessRequestDetailsDto = new ConnectionAccessRequestDetailsDto();
         this.copyCommonFields(connectionAccessRequest, connectionAccessRequestDetailsDto);
         detailsDto = connectionAccessRequestDetailsDto;
      }

      return Optional.of(detailsDto);
   }

   public void create(ConnectionAccessRequestCreateDto connectionAccessRequestCreateDto) throws Exception {
      this.checkIfUserAlreadyHasAccessToConnection(
         connectionAccessRequestCreateDto.getIpAddress(), connectionAccessRequestCreateDto.getPort(), connectionAccessRequestCreateDto.getType()
      );
      RepositoryContextManager.startNewTransaction();

      try {
         ConnectionAccessRequest connectionAccessRequest = new ConnectionAccessRequest();
         String identifier = UUID.randomUUID().toString();

         while (this.connectionAccessRequestRepository.existsByIdentifier(identifier)) {
            identifier = UUID.randomUUID().toString();
         }

         connectionAccessRequest.setIdentifier(identifier);
         connectionAccessRequest.setApplicationTime(Instant.now().getEpochSecond());
         connectionAccessRequest.setIpAddress(connectionAccessRequestCreateDto.getIpAddress());
         connectionAccessRequest.setPort(connectionAccessRequestCreateDto.getPort());
         connectionAccessRequest.setType(connectionAccessRequestCreateDto.getType());
         connectionAccessRequest.setClipboardEnabled(connectionAccessRequestCreateDto.isClipboardEnabled());
         connectionAccessRequest.setFileTransferMode(connectionAccessRequestCreateDto.getFileTransferMode());
         connectionAccessRequest.setDescription(connectionAccessRequestCreateDto.getDescription());
         connectionAccessRequest.setStatus(ConnectionAccessRequestStatus.NOT_CHECKED);
         User user = this.userService.getOneById(this.authorizationService.getCurrentUserInfo().getId(), false);
         user.addConnectionAccessRequest(connectionAccessRequest);
         connectionAccessRequest.setUser(user);
         this.crudRepository.save(connectionAccessRequest);
         this.userService.save(user);
         RepositoryContextManager.commit();
         this.asyncTaskExecutor
            .executeTask(
               new ConnectionAccessRequestCrudServiceImpl.SendNotificationToAdminsTask(
                  connectionAccessRequest, this.authorizationService.getCurrentUserInfo().getUsername(), true
               ),
               true
            );
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }
   }

   public void update(String identifier, ConnectionAccessRequestUpdateDto connectionAccessRequestUpdateDto) throws Exception {
      this.checkIfUserAlreadyHasAccessToConnection(
         connectionAccessRequestUpdateDto.getIpAddress(), connectionAccessRequestUpdateDto.getPort(), connectionAccessRequestUpdateDto.getType()
      );
      ConnectionAccessRequest connectionAccessRequest = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionAccessRequestWithUserByIdentifier(identifier), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionAccessRequest.class)));
      RepositoryContextManager.startNewTransaction();

      try {
         if (!connectionAccessRequest.getUser().getUsername().equalsIgnoreCase(this.authorizationService.getCurrentUserInfo().getUsername())) {
            throw new ConnectionAccessRequestOwnershipException();
         } else {
            this.checkIfRequestIsLocked(connectionAccessRequest);
            connectionAccessRequest.setIpAddress(connectionAccessRequestUpdateDto.getIpAddress());
            connectionAccessRequest.setPort(connectionAccessRequestUpdateDto.getPort());
            connectionAccessRequest.setType(connectionAccessRequestUpdateDto.getType());
            connectionAccessRequest.setClipboardEnabled(connectionAccessRequestUpdateDto.isClipboardEnabled());
            connectionAccessRequest.setFileTransferMode(connectionAccessRequestUpdateDto.getFileTransferMode());
            connectionAccessRequest.setDescription(connectionAccessRequestUpdateDto.getDescription());
            this.crudRepository.update(connectionAccessRequest);
            RepositoryContextManager.commit();
            this.asyncTaskExecutor
               .executeTask(
                  new ConnectionAccessRequestCrudServiceImpl.SendNotificationToAdminsTask(
                     connectionAccessRequest, this.authorizationService.getCurrentUserInfo().getUsername(), false
                  ),
                  true
               );
         }
      } catch (Exception var5) {
         RepositoryContextManager.rollback();
         throw var5;
      }
   }

   public void delete(String identifier) throws Exception {
      ConnectionAccessRequest connectionAccessRequest = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionAccessRequestWithUserByIdentifier(identifier), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionAccessRequest.class)));
      RepositoryContextManager.startNewTransaction();

      try {
         if (!connectionAccessRequest.getUser().getUsername().equalsIgnoreCase(this.authorizationService.getCurrentUserInfo().getUsername())) {
            throw new ConnectionAccessRequestOwnershipException();
         } else {
            connectionAccessRequest.getUser().removeConnectionAccessRequest(connectionAccessRequest);
            this.crudRepository.remove(connectionAccessRequest);
            RepositoryContextManager.commit();
         }
      } catch (Exception var4) {
         RepositoryContextManager.rollback();
         throw var4;
      }
   }

   @Override
   public void reviewRequest(String identifier, ConnectionAccessRequestReviewDto connectionAccessRequestReviewDto) throws Exception {
      ConnectionAccessRequest connectionAccessRequest = Optional.ofNullable(
            this.jpaQueryBasedReadRepository.findOne(this.fetchConnectionAccessRequestWithUserByIdentifier(identifier), false)
         )
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(ConnectionAccessRequest.class)));
      this.checkIfRequestIsLocked(connectionAccessRequest);
      RepositoryContextManager.startNewTransaction();

      try {
         connectionAccessRequest.setStatus(
            connectionAccessRequestReviewDto.isApproved() ? ConnectionAccessRequestStatus.APPROVED : ConnectionAccessRequestStatus.DISAPPROVED
         );
         connectionAccessRequest.setAdminReviewNote(connectionAccessRequestReviewDto.getNote());
         String accessRuleName = null;
         if (connectionAccessRequest.getStatus().equals(ConnectionAccessRequestStatus.APPROVED)) {
            boolean createManually = true;
            if (StringUtils.hasContent(connectionAccessRequestReviewDto.getAccessRuleName())) {
               try {
                  this.accessRuleService.addUser(connectionAccessRequestReviewDto.getAccessRuleName(), connectionAccessRequest.getUser());
                  createManually = false;
               } catch (ResourceNotFoundException var11) {
               }
            }

            if (createManually) {
               boolean connectionAlreadyExists = false;

               String connectionName;
               try {
                  Connection connection = this.connectionService
                     .getOneByHostInfo(connectionAccessRequest.getType(), connectionAccessRequest.getIpAddress(), connectionAccessRequest.getPort(), false);
                  connectionName = connection.getName();
                  connectionAlreadyExists = true;
               } catch (ResourceNotFoundException var10) {
                  connectionName = String.format(
                     "REQUESTED_%s_%s_%s",
                     connectionAccessRequest.getType().toString(),
                     connectionAccessRequest.getIpAddress(),
                     connectionAccessRequest.getPort()
                  );
                  this.connectionService
                     .createNewRecord(
                        connectionName,
                        connectionAccessRequest.getType(),
                        connectionAccessRequest.getIpAddress(),
                        connectionAccessRequest.getPort(),
                        connectionAccessRequest.isClipboardEnabled(),
                        connectionAccessRequest.getFileTransferMode(),
                        connectionAccessRequestReviewDto.getCredential(),
                        connectionAccessRequestReviewDto.getBanners(),
                        connectionAccessRequestReviewDto.getSessionInputConstraints(),
                        connectionAccessRequestReviewDto.getAccessibilityTimePeriodConstraint()
                     );
               }

               accessRuleName = connectionAlreadyExists
                  ? String.format("%s_ACCESS_RULE", String.format("%s_REQUESTED", connectionName))
                  : String.format("%s_ACCESS_RULE", connectionName);
               String credential = !connectionAlreadyExists && connectionAccessRequestReviewDto.getCredential() != null
                  ? connectionAccessRequestReviewDto.getCredential().getLabel()
                  : null;
               this.accessRuleService
                  .createNewRecord(
                     accessRuleName,
                     connectionName,
                     credential,
                     Stream.of(connectionAccessRequest.getUser().getUsername()).collect(Collectors.toSet()),
                     null,
                     connectionAccessRequest.isClipboardEnabled(),
                     connectionAccessRequest.getFileTransferMode()
                  );
            }
         }

         this.crudRepository.update(connectionAccessRequest);
         RepositoryContextManager.commit();
         this.asyncTaskExecutor
            .executeTask(
               new ConnectionAccessRequestCrudServiceImpl.SendNotificationToApplicantTask(
                  connectionAccessRequest, connectionAccessRequest.getUser(), accessRuleName
               ),
               true
            );
      } catch (Exception var12) {
         RepositoryContextManager.rollback();
         throw var12;
      }
   }

   private boolean isAdminUser() {
      return this.authorizationService.getCurrentUserInfo().getRole().equalsIgnoreCase("SUPERUSER");
   }

   private void fixSortingProperty(Sorting sorting) {
      sorting.setProperty(String.format("car.%s", sorting.getProperty()));
   }

   private List<LinkedFilter>[] processFilters(List<LinkedFilter> filters) {
      List<LinkedFilter> requestsFilter = new ArrayList<>();
      List<LinkedFilter> userFilter = new ArrayList<>();
      if (filters != null) {
         for (LinkedFilter filter : filters) {
            if (filter.getFilter().getProperty().equalsIgnoreCase("applicant")) {
               filter.getFilter().setProperty("username");
               userFilter.add(filter);
            } else {
               requestsFilter.add(filter);
            }
         }
      }

      return new List[]{requestsFilter, userFilter};
   }

   private void addApplicantIdFilter(List<LinkedFilter> filters) {
      filters.add(new FilterBuilder().number("id").eq(this.authorizationService.getCurrentUserInfo().getId()).buildSingle());
   }

   private JpaQuery<ConnectionAccessRequest> fetchConnectionAccessRequestWithUserByIdentifier(String identifier) {
      return new JpaQueryBuilder()
         .from(ConnectionAccessRequest.class, "c")
         .join("user", "u")
         .fetch()
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("identifier", identifier))
         .build();
   }

   private ConnectionAccessRequestReviewListDto convertTupleToConnectionAccessRequestApprovalListDto(Tuple tuple) {
      ConnectionAccessRequestReviewListDto connectionAccessRequestReviewListDto = new ConnectionAccessRequestReviewListDto();
      this.copyCommonFields(tuple, connectionAccessRequestReviewListDto);
      connectionAccessRequestReviewListDto.setApplicant((String)tuple.get("username", String.class));
      return connectionAccessRequestReviewListDto;
   }

   private ConnectionAccessRequestListDto convertTupleToConnectionAccessRequestListDto(Tuple tuple) {
      ConnectionAccessRequestListDto connectionAccessRequestListDto = new ConnectionAccessRequestListDto();
      this.copyCommonFields(tuple, connectionAccessRequestListDto);
      return connectionAccessRequestListDto;
   }

   private void copyCommonFields(Tuple tuple, ConnectionAccessRequestListDto connectionAccessRequestCommonListDto) {
      connectionAccessRequestCommonListDto.setIdentifier((String)tuple.get("identifier", String.class));
      connectionAccessRequestCommonListDto.setApplicationTime(((Number)tuple.get("applicationTime")).longValue());
      connectionAccessRequestCommonListDto.setIpAddress((String)tuple.get("ipAddress", String.class));
      connectionAccessRequestCommonListDto.setPort(((Number)tuple.get("port")).intValue());
      connectionAccessRequestCommonListDto.setType(
         this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type")).intValue()))
      );
      connectionAccessRequestCommonListDto.setClipboardEnabled((Boolean)tuple.get("clipboardEnabled", Boolean.class));
      connectionAccessRequestCommonListDto.setFileTransferMode(
         this.fileTransferModeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("fileTransferMode")).intValue()))
      );
      connectionAccessRequestCommonListDto.setStatus(
         this.connectionAccessRequestStatusConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("status")).intValue()))
      );
   }

   private void copyCommonFields(ConnectionAccessRequest connectionAccessRequest, ConnectionAccessRequestDetailsDto connectionAccessRequestDetailsDto) {
      connectionAccessRequestDetailsDto.setIdentifier(connectionAccessRequest.getIdentifier());
      connectionAccessRequestDetailsDto.setApplicationTime(connectionAccessRequest.getApplicationTime());
      connectionAccessRequestDetailsDto.setType(connectionAccessRequest.getType());
      connectionAccessRequestDetailsDto.setIpAddress(connectionAccessRequest.getIpAddress());
      connectionAccessRequestDetailsDto.setPort(connectionAccessRequest.getPort());
      connectionAccessRequestDetailsDto.setClipboardEnabled(connectionAccessRequest.isClipboardEnabled());
      connectionAccessRequestDetailsDto.setFileTransferMode(connectionAccessRequest.getFileTransferMode());
      connectionAccessRequestDetailsDto.setStatus(connectionAccessRequest.getStatus());
      connectionAccessRequestDetailsDto.setDescription(connectionAccessRequest.getDescription());
      connectionAccessRequestDetailsDto.setAdminReviewNote(connectionAccessRequest.getAdminReviewNote());
   }

   private void checkIfRequestIsLocked(ConnectionAccessRequest connectionAccessRequest) throws ConnectionAccessRequestLockedException {
      if (!connectionAccessRequest.getStatus().equals(ConnectionAccessRequestStatus.NOT_CHECKED)) {
         throw new ConnectionAccessRequestLockedException();
      }
   }

   private void checkIfUserAlreadyHasAccessToConnection(String ipAddress, int port, ConnectionType type) throws AlreadyHasAccessToRequestedHostException {
      String accessRuleName = this.connectionService
         .hasUserAlreadyAccessedToHost(this.authorizationService.getCurrentUserInfo().getId(), ipAddress, port, type);
      if (StringUtils.hasContent(accessRuleName)) {
         throw new AlreadyHasAccessToRequestedHostException(accessRuleName);
      }
   }

   static {
      ADMIN_COLUMN_LIST[COLUMN_LIST.length] = "u.username";
   }

   private class SendNotificationToAdminsTask implements Runnable {
      private static final String SUBJECT_CODE = "connection_access_request.request.message_subject";
      private static final String NEW_REQUEST_MESSAGE_CODE = "connection_access_request.request.new_request_message";
      private static final String UPDATED_REQUEST_MESSAGE_CODE = "connection_access_request.request.updated_request_message";
      private final ConnectionAccessRequest connectionAccessRequest;
      private final String applicant;
      private final boolean creationMode;

      private SendNotificationToAdminsTask(ConnectionAccessRequest connectionAccessRequest, String applicant, boolean creationMode) {
         this.connectionAccessRequest = connectionAccessRequest;
         this.applicant = applicant;
         this.creationMode = creationMode;
      }

      @Override
      public void run() {
         NativeQuery fetchAdminsInfoQuery = new NativeQueryBuilder()
            .select("u.username", "u.email", "u.phoneNumber", "u.locale")
            .from(User.class, "u")
            .join(Role.class, "r")
            .on("role_id", "id")
            .joinWhere(new FilterChainBuilder().filter(new FilterBuilder().string("title").eq("SUPERUSER").buildSingle()).build())
            .build();
         List<String[]> adminsInfo = ConnectionAccessRequestCrudServiceImpl.this.nativeQueryBasedReadRepository
            .findAll(
               fetchAdminsInfoQuery,
               tuple -> new String[]{
                     (String)tuple.get("username", String.class),
                     (String)tuple.get("email", String.class),
                     (String)tuple.get("phoneNumber", String.class),
                     (String)tuple.get("locale", String.class)
                  }
            );
         String host = String.format("%s:%d", this.connectionAccessRequest.getIpAddress(), this.connectionAccessRequest.getPort());

         for (String[] info : adminsInfo) {
            String username = info[0];
            String email = info[1];
            String phoneNumber = info[2];
            Locale locale = new Locale(info[3]);
            String message = ConnectionAccessRequestCrudServiceImpl.this.messageResolver
               .getMessage(
                  this.creationMode ? "connection_access_request.request.new_request_message" : "connection_access_request.request.updated_request_message",
                  locale,
                  this.applicant,
                  host,
                  this.connectionAccessRequest.getIdentifier()
               );

            try {
               ConnectionAccessRequestCrudServiceImpl.this.notificationService
                  .broadCastMessage(
                     new ServerEvent(ServerEventType.MESSAGE, message, SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()),
                     Stream.of(username).collect(Collectors.toSet())
                  );
               String subject = ConnectionAccessRequestCrudServiceImpl.this.messageResolver
                  .getMessage("connection_access_request.request.message_subject", locale);
               if (StringUtils.hasContent(email) && ConnectionAccessRequestCrudServiceImpl.this.emailSender.configured()) {
                  ConnectionAccessRequestCrudServiceImpl.this.emailSender.send(email, subject, message);
               }

               if (StringUtils.hasContent(phoneNumber) && ConnectionAccessRequestCrudServiceImpl.this.smsSender.isConfigured()) {
                  String titledMessage = String.format("%s\n%s", subject, message);
                  ConnectionAccessRequestCrudServiceImpl.this.smsSender.send(phoneNumber, titledMessage);
               }
            } catch (Exception var13) {
               var13.printStackTrace();
            }
         }
      }
   }

   private class SendNotificationToApplicantTask implements Runnable {
      private static final String APPROVAL_SUBJECT_CODE = "connection_access_request.review.approved_message_subject";
      private static final String DISAPPROVAL_SUBJECT_CODE = "connection_access_request.review.disapproved_message_subject";
      private static final String APPROVAL_MESSAGE_CODE = "connection_access_request.review.request_approved";
      private static final String DISAPPROVAL_MESSAGE_CODE = "connection_access_request.review.request_disapproved";
      private final ConnectionAccessRequest connectionAccessRequest;
      private final User user;
      private final String grantedAccessRuleName;

      private SendNotificationToApplicantTask(ConnectionAccessRequest connectionAccessRequest, User user, String grantedAccessRuleName) {
         this.connectionAccessRequest = connectionAccessRequest;
         this.user = user;
         this.grantedAccessRuleName = grantedAccessRuleName;
      }

      @Override
      public void run() {
         Locale locale = new Locale(this.user.getLocale());
         boolean approved = this.connectionAccessRequest.getStatus().equals(ConnectionAccessRequestStatus.APPROVED);
         String host = String.format("%s:%d", this.connectionAccessRequest.getIpAddress(), this.connectionAccessRequest.getPort());
         String message = approved
            ? ConnectionAccessRequestCrudServiceImpl.this.messageResolver
               .getMessage(
                  "connection_access_request.review.request_approved", locale, host, this.grantedAccessRuleName, this.connectionAccessRequest.getIdentifier()
               )
            : ConnectionAccessRequestCrudServiceImpl.this.messageResolver
               .getMessage("connection_access_request.review.request_disapproved", locale, host, this.connectionAccessRequest.getIdentifier());
         Set<String> users = Stream.of(this.user.getUsername()).collect(Collectors.toSet());

         try {
            ConnectionAccessRequestCrudServiceImpl.this.notificationService
               .broadCastMessage(
                  new ServerEvent(ServerEventType.MESSAGE, message, SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()), users
               );
            String subject = ConnectionAccessRequestCrudServiceImpl.this.messageResolver
               .getMessage(
                  approved ? "connection_access_request.review.approved_message_subject" : "connection_access_request.review.disapproved_message_subject",
                  locale
               );
            String email = this.user.getEmail();
            if (StringUtils.hasContent(email) && ConnectionAccessRequestCrudServiceImpl.this.emailSender.configured()) {
               ConnectionAccessRequestCrudServiceImpl.this.emailSender.send(email, subject, message);
            }

            String phoneNumber = this.user.getPhoneNumber();
            if (StringUtils.hasContent(phoneNumber) && ConnectionAccessRequestCrudServiceImpl.this.smsSender.isConfigured()) {
               String titledMessage = String.format("%s\n%s", subject, message);
               ConnectionAccessRequestCrudServiceImpl.this.smsSender.send(phoneNumber, titledMessage);
            }
         } catch (Exception var10) {
         }
      }
   }
}
