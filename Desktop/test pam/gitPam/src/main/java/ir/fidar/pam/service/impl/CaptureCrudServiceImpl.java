package ir.fidar.pam.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.InvalidPageException;
import ir.fidar.core.exception.SseConnectionBrokenException;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.SystemConstantsAndDefaults;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.security.service.AuthorizationService;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.service.management.NotificationService;
import ir.fidar.core.util.HttpMimeType;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.WebUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.core.util.filter.convert.FilterConversionService;
import ir.fidar.pam.da.repository.BridgeRepository;
import ir.fidar.pam.da.repository.CaptureRepository;
import ir.fidar.pam.da.repository.SessionCapturedImageRepository;
import ir.fidar.pam.da.repository.SessionCapturedImageTextRepository;
import ir.fidar.pam.domain.dto.SessionInputConstraintViolationIncidentDetailsDto;
import ir.fidar.pam.domain.dto.SessionTransferredFileDetailsDto;
import ir.fidar.pam.domain.dto.capture.CaptureClientInformationDetailsDto;
import ir.fidar.pam.domain.dto.capture.CaptureDetailsDto;
import ir.fidar.pam.domain.dto.capture.CaptureExecutedCommandListDto;
import ir.fidar.pam.domain.dto.capture.CaptureKeyEventDto;
import ir.fidar.pam.domain.dto.capture.CaptureListDto;
import ir.fidar.pam.domain.dto.capture.CaptureSpecialFilterType;
import ir.fidar.pam.domain.dto.capture.CaptureTransferredClipboardListDto;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.domain.model.ocr.SessionCapturedImage;
import ir.fidar.pam.domain.model.ocr.SessionCapturedImageText;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.domain.model.session.CaptureTransferredClipboard;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.model.session.SessionTransferredFile;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.converter.attribbute.CaptureStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.exception.CaptureExecutedCommandNotSupportedException;
import ir.fidar.pam.exception.NoImagesCapturedFromSessionBasedOnRuleException;
import ir.fidar.pam.exception.TransferredFileNotFound;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.management.ConverterHostProperties;
import ir.fidar.pam.service.CaptureCrudService;
import ir.fidar.pam.service.CaptureExecutedCommandService;
import ir.fidar.pam.service.CaptureTransferredClipboardService;
import ir.fidar.pam.service.connection.ConnectionService;
import ir.fidar.pam.session.OcrHttpClient;
import ir.fidar.pam.session.ocr.OcrHostProperties;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Tuple;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Request.Builder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import reactor.core.publisher.Flux;

@Service
public class CaptureCrudServiceImpl extends GlobalCommonServiceImpl<Capture> implements CaptureCrudService {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final Set<String> LIVE_RECORD_FILE_FETCH_REQUESTS = new HashSet<>();
   private static final String RECORD_FILE_OFFSET_HEADER = "record-file-offset";
   private static final String RECORD_FILE_UUID_HEADER = "record-file-uuid";
   private static final String RECORD_FILE_END_HEADER = "record-file-end";
   private static final String FILE_TRANSFER_FILTER_PROPERTY_NAME = "transferred-file.";
   private static final String CONSTRAINT_VIOLATION_FILTER_PROPERTY_NAME = "input-const.";
   private static final String[] LIST_COLUMNS = new String[]{
           "c.session_id",
           "c.status",
           "c.owner",
           "c.connection_name",
           "c.bridge_name",
           "c.type",
           "c.connection_ip_address",
           "c.start_time",
           "c.end_time",
           "c.access_rule_uuid"
   };
   private final CaptureRepository captureRepository;
   private final BridgeRepository bridgeRepository;
   private final ConverterHostProperties converterHostProperties;
   private final SessionCapturedImageRepository sessionCapturedImageRepository;
   private final SessionCapturedImageTextRepository sessionCapturedImageTextRepository;
   private final OcrHostProperties ocrHostProperties;
   private final ObjectMapper objectMapper;
   private final NotificationService notificationService;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private final ConnectionTypeConverter connectionTypeConverter;
   private final CaptureStatusConverter captureStatusConverter;
   private final ConnectionService connectionService;
   private final CaptureRuleService captureRuleService;
   private final CaptureTransferredClipboardService captureTransferredClipboardService;
   private final CaptureExecutedCommandService captureExecutedCommandService;
   private final FilterConversionService filterConversionService;
   private final OcrHttpClient ocrHttpClient;

   public CaptureCrudServiceImpl(
           CaptureRepository captureRepository,
           AuthorizationService authorizationService,
           BridgeRepository bridgeRepository,
           ConverterHostProperties converterHostProperties,
           SessionCapturedImageRepository sessionCapturedImageRepository,
           SessionCapturedImageTextRepository sessionCapturedImageTextRepository,
           OcrHostProperties ocrHostProperties,
           ObjectMapper objectMapper,
           NotificationService notificationService,
           AsyncTaskExecutor asyncTaskExecutor,
           ConnectionService connectionService,
           CaptureRuleService captureRuleService,
           CaptureTransferredClipboardService captureTransferredClipboardService,
           CaptureExecutedCommandService captureExecutedCommandService,
           FilterConversionService filterConversionService,
           OcrHttpClient ocrHttpClient
   ) {
      super(captureRepository);
      this.captureRepository = captureRepository;
      this.captureRuleService = captureRuleService;
      this.captureTransferredClipboardService = captureTransferredClipboardService;
      this.captureExecutedCommandService = captureExecutedCommandService;
      this.filterConversionService = filterConversionService;
      this.ocrHttpClient = ocrHttpClient;
      this.authorizationService = authorizationService;
      this.bridgeRepository = bridgeRepository;
      this.converterHostProperties = converterHostProperties;
      this.sessionCapturedImageRepository = sessionCapturedImageRepository;
      this.sessionCapturedImageTextRepository = sessionCapturedImageTextRepository;
      this.ocrHostProperties = ocrHostProperties;
      this.objectMapper = objectMapper;
      this.notificationService = notificationService;
      this.asyncTaskExecutor = asyncTaskExecutor;
      this.connectionService = connectionService;
      this.connectionTypeConverter = new ConnectionTypeConverter();
      this.captureStatusConverter = new CaptureStatusConverter();
   }

   @Override
   public Optional<List<ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      Collection<String> connectionNames = this.connectionService.getAllConnectionsThatCurrentUserCanReviewTheirCaptures();
      if (connectionNames.isEmpty()) {
         return Optional.empty();
      } else {
         CaptureCrudServiceImpl.ProcessedFilters processedFilters = this.preprocessFilters(filters);
         if (!processedFilters.containsSpecialFilter()) {
            filters.add(new FilterBuilder().list("connectionName").in(connectionNames).buildSingle());
            NativeQuery query = new NativeQueryBuilder()
                    .select(LIST_COLUMNS)
                    .from(Capture.class, "c")
                    .where(new FilterChainBuilder().filter(processedFilters.getMainFilters()).build())
                    .orderBy(sorting)
                    .build();
            return Optional.of(this.nativeQueryBasedReadRepository.findAll(query, this::convertTupleToCaptureListDto));
         } else {
            String query = this.generateLoadRecordListQuery(processedFilters, null, sorting);
            EntityManager entityManager = RepositoryContextManager.getUnderlyingEntityManager();
            Query jpaQuery = entityManager.createNativeQuery(query, Tuple.class)
                    .setHint("org.hibernate.readOnly", Boolean.TRUE)
                    .setParameter("conNames", connectionNames);

            for (CaptureCrudServiceImpl.SpecialFilter specialFilter : processedFilters.getSpecialFilters()) {
               jpaQuery = jpaQuery.setParameter(specialFilter.getFilterType().getTargetField(), specialFilter.getFilter().getFilter().getValue());
            }

            List<Tuple> records = jpaQuery.getResultList();
            return Optional.of(records.stream().map(this::convertTupleToCaptureListDto).collect(Collectors.toList()));
         }
      }
   }

   @Override
   public Optional<CustomPageDto<ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws InvalidPageException {
      Collection<String> connectionNames = this.connectionService.getAllConnectionsThatCurrentUserCanReviewTheirCaptures();
      if (connectionNames.isEmpty()) {
         return Optional.empty();
      } else {
         CaptureCrudServiceImpl.ProcessedFilters processedFilters = this.preprocessFilters(filters);
         if (!processedFilters.containsSpecialFilter()) {
            processedFilters.getMainFilters().add(new FilterBuilder().list("connectionName").in(connectionNames).buildSingle());
            NativePaginationQuery query = (NativePaginationQuery)new NativePaginationQueryBuilder()
                    .page(pageable)
                    .select(LIST_COLUMNS)
                    .from(Capture.class, "c")
                    .where(new FilterChainBuilder().filter(processedFilters.getMainFilters()).build())
                    .orderBy(sorting)
                    .build();
            return Optional.of(this.nativeQueryBasedReadRepository.find(query, this::convertTupleToCaptureListDto));
         } else {
            String query = this.generateLoadRecordListQuery(processedFilters, pageable, sorting);
            EntityManager entityManager = RepositoryContextManager.getUnderlyingEntityManager();
            Query jpaQuery = entityManager.createNativeQuery(query, Tuple.class)
                    .setHint("org.hibernate.readOnly", Boolean.TRUE)
                    .setParameter("conNames", connectionNames);

            for (CaptureCrudServiceImpl.SpecialFilter specialFilter : processedFilters.getSpecialFilters()) {
               jpaQuery = jpaQuery.setParameter(specialFilter.getFilterType().getTargetField(), specialFilter.getFilter().getFilter().getValue());
            }

            List<Tuple> records = jpaQuery.getResultList();
            int totalElements = records.size() > 0 ? ((Number)records.get(0).get("TOTAL_ELEMENTS", Number.class)).intValue() : 0;
            int totalPages = totalElements / pageable.getPageSize();
            if (totalElements % pageable.getPageSize() != 0) {
               totalPages++;
            }

            return Optional.of(
                    new CustomPageDto<>(records.stream().map(this::convertTupleToCaptureListDto).collect(Collectors.toList()), (long)totalElements, (long)totalPages)
            );
         }
      }
   }

   @Transactional
   @Override
   public Optional<DetailsDto> load(String sessionId) throws InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      CaptureDetailsDto captureDetailsDto = new CaptureDetailsDto();
      captureDetailsDto.setSessionId(capture.getSessionId());
      captureDetailsDto.setStartTime(capture.getStartTime());
      captureDetailsDto.setEndTime(capture.getEndTime());
      captureDetailsDto.setType(capture.getType());
      captureDetailsDto.setOwner(capture.getOwner());
      captureDetailsDto.setConnectionName(capture.getConnectionName());
      captureDetailsDto.setConnectionIpAddress(capture.getConnectionIpAddress());
      captureDetailsDto.setConnectionPort(capture.getConnectionPort());
      captureDetailsDto.setBridgeName(capture.getBridgeName());
      captureDetailsDto.setBridgeIpAddress(capture.getBridgeIpAddress());
      captureDetailsDto.setStatus(capture.getStatus());
      captureDetailsDto.setActiveFileTransferMode(capture.getActiveFileTransferMode());
      captureDetailsDto.setHadClipboard(capture.isHadClipboard());
      captureDetailsDto.setCredentialLabel(capture.getCredentialLabel());
      File captureFile = new File(String.format("/records/%s/%s.mp4", capture.getAccessRuleUuid(), capture.getSessionId()));
      if (captureFile.exists()) {
         captureDetailsDto.setVideoSize(captureFile.length());
      }

      List<SessionInputConstraintViolationIncidentDetailsDto> sessionInputConstraintViolationIncidentDetailsDtoList = null;
      if (capture.getSessionInputConstraintViolationIncidents() != null) {
         sessionInputConstraintViolationIncidentDetailsDtoList = new ArrayList<>();

         for (SessionInputConstraintViolationIncident sessionInputConstraintViolationIncident : capture.getSessionInputConstraintViolationIncidents()) {
            SessionInputConstraintViolationIncidentDetailsDto sessionInputConstraintViolationIncidentDetailsDto = new SessionInputConstraintViolationIncidentDetailsDto(

            );
            sessionInputConstraintViolationIncidentDetailsDto.setInput(sessionInputConstraintViolationIncident.getInput());
            sessionInputConstraintViolationIncidentDetailsDto.setRegex(sessionInputConstraintViolationIncident.getRegex());
            sessionInputConstraintViolationIncidentDetailsDto.setTime(sessionInputConstraintViolationIncident.getTime());
            sessionInputConstraintViolationIncidentDetailsDtoList.add(sessionInputConstraintViolationIncidentDetailsDto);
         }
      }

      captureDetailsDto.setSessionInputConstraintViolationIncidents(sessionInputConstraintViolationIncidentDetailsDtoList);
      List<SessionTransferredFileDetailsDto> sessionTransferredFileDetailsDtoList = null;
      if (capture.getSessionTransferredFiles() != null) {
         sessionTransferredFileDetailsDtoList = new ArrayList<>();

         for (SessionTransferredFile sessionTransferredFile : capture.getSessionTransferredFiles()) {
            SessionTransferredFileDetailsDto sessionTransferredFileDetailsDto = new SessionTransferredFileDetailsDto();
            sessionTransferredFileDetailsDto.setName(sessionTransferredFile.getName());
            sessionTransferredFileDetailsDto.setMode(sessionTransferredFile.getMode());
            sessionTransferredFileDetailsDto.setStatus(sessionTransferredFile.getStatus());
            sessionTransferredFileDetailsDto.setTime(sessionTransferredFile.getTime());
            sessionTransferredFileDetailsDtoList.add(sessionTransferredFileDetailsDto);
         }
      }

      captureDetailsDto.setSessionTransferredFiles(sessionTransferredFileDetailsDtoList);
      if (capture.getClientInformation() != null) {
         CaptureClientInformationDetailsDto clientInformationDetailsDto = new CaptureClientInformationDetailsDto();
         clientInformationDetailsDto.setScreenWidth(capture.getClientInformation().getScreenWidth());
         clientInformationDetailsDto.setScreenHeight(capture.getClientInformation().getScreenHeight());
         clientInformationDetailsDto.setScreenDpi(capture.getClientInformation().getScreenDpi());
         captureDetailsDto.setClientInformation(clientInformationDetailsDto);
      }

      return Optional.of(captureDetailsDto);
   }

   @Override
   public StreamingResponseBody downloadRecordFile(String sessionId) throws IOException, InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
      String uuid = request.getHeader("record-file-uuid");
      String offset = request.getHeader("record-file-offset");
      boolean uuidProvided = StringUtils.hasContent(uuid);
      boolean uuidAlreadyRegistered = LIVE_RECORD_FILE_FETCH_REQUESTS.contains(uuid);
      boolean live = capture.getStatus() == CaptureStatus.LIVE;
      if (!uuidProvided || !uuidAlreadyRegistered) {
         this.checkUserAccessibility(capture, true);
      }

      Bridge bridge = this.bridgeRepository.findOneByNameIgnoreCase(capture.getBridgeName());
      String fileNamePath = bridge.getRecordsStoragePath() + "/" + capture.getAccessRuleUuid() + "/" + capture.getSessionId();
      HttpServletResponse response = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getResponse();
      File captureFile = new File(fileNamePath);
      if (live || uuidProvided && uuidAlreadyRegistered) {
         long offsetAsLong = 0L;

         try {
            offsetAsLong = Long.parseLong(offset);
            offsetAsLong = offsetAsLong < 0L ? 0L : offsetAsLong;
         } catch (NumberFormatException var18) {
            offsetAsLong = 0L;
         }

         if (uuidAlreadyRegistered) {
            LIVE_RECORD_FILE_FETCH_REQUESTS.remove(uuid);
         }

         if (!live) {
            response.setHeader("record-file-end", "end");
         } else {
            uuid = UUID.randomUUID().toString();
            LIVE_RECORD_FILE_FETCH_REQUESTS.add(uuid);
            response.setHeader("record-file-uuid", uuid);
            response.setHeader("record-file-offset", String.valueOf(captureFile.length()));
         }

         RandomAccessFile randomAccessFile = new RandomAccessFile(captureFile, "r");
         randomAccessFile.seek(offsetAsLong);
         int bufferSize = 8192;
         byte[] buffer = new byte[bufferSize];
         return outputStream -> {
            while (true) {
               int numberOfReadByte = randomAccessFile.read(buffer);
               if (numberOfReadByte == -1) {
                  return;
               }

               if (numberOfReadByte == buffer.length) {
                  outputStream.write(buffer);
               } else {
                  outputStream.write(Arrays.copyOfRange(buffer, 0, numberOfReadByte));
               }
            }
         };
      } else {
         return WebUtils.streamFile(response, captureFile, HttpMimeType.TEXT.getValue());
      }
   }

   @Override
   public StreamingResponseBody convertToVideo(String sessionId, String fileName, int bitrate) throws InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException, IOException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, false);
      Bridge bridge = this.bridgeRepository.findOneByNameIgnoreCase(capture.getBridgeName());
      String accessRuleUuid = capture.getAccessRuleUuid();
      String path = String.format("%s/%s", bridge.getRecordsStoragePath(), accessRuleUuid);
      String sessionFilePath = String.format("%s/%s", path, sessionId);
      String videoStoragePath = String.format("%s.mp4", sessionFilePath, bitrate);
      String downloadFileName = String.format("%s.mp4", fileName);
      File recordingPath = new File(path);
      File[] files = recordingPath.listFiles();
      HttpServletResponse httpServletResponse = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getResponse();

      try {
         File deletingFile = null;

         for (File file : files) {
            String processingFileName = file.getAbsolutePath();
            if (processingFileName.equalsIgnoreCase(videoStoragePath)) {
               return WebUtils.streamFile(httpServletResponse, file, downloadFileName, HttpMimeType.VIDEO_MP4.getValue());
            }

            if (processingFileName.startsWith(sessionId) && processingFileName.endsWith(".mp4")) {
               deletingFile = file;
               break;
            }
         }

         if (deletingFile != null) {
            deletingFile.delete();
         }

         HttpServletRequest httpServletRequest = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getRequest();
         String query = StringUtils.hasContent(httpServletRequest.getQueryString())
                 ? "?" + httpServletRequest.getQueryString()
                 : httpServletRequest.getQueryString();
         String downloadUrl = httpServletRequest.getRequestURI() + query;
         String username = this.authorizationService.getCurrentUserInfo().getUsername();
         this.asyncTaskExecutor
                 .executeTask(
                         () -> {
                            try {
                               StringBuilder urlBuilder = new StringBuilder("http://")
                                       .append(this.converterHostProperties.getIpAddress())
                                       .append(":")
                                       .append(this.converterHostProperties.getPort())
                                       .append("/api/convert?bitrate=")
                                       .append(bitrate)
                                       .append("&path=")
                                       .append(sessionFilePath)
                                       .append("&audio=")
                                       .append(capture.getType().equals(ConnectionType.RDP) || capture.getType().equals(ConnectionType.VNC));
                               Request request = new Builder().url(urlBuilder.toString()).get().build();
                               OkHttpClient client = new OkHttpClient(
                                       new okhttp3.OkHttpClient.Builder().readTimeout(0L, TimeUnit.SECONDS).writeTimeout(0L, TimeUnit.SECONDS)
                               );
                               client.callTimeoutMillis();

                               try {
                                  Response responsex = client.newCall(request).execute();
                                  Throwable var11x = null;

                                  try {
                                     if (responsex.code() == 200) {
                                        File file = new File(String.format("%s.mp4", sessionFilePath));
                                        if (!file.exists()) {
                                           throw new IllegalStateException();
                                        }

                                        this.sendCaptureVideoDownloadNotification(downloadUrl, downloadFileName, file.length(), username, true);
                                     } else {
                                        LOGGER.error(
                                                "An unexpected error occurred while requesting to 'converter' module for session with id '{}'", capture.getSessionId()
                                        );
                                        this.sendCaptureVideoDownloadNotification(downloadUrl, downloadFileName, 0L, username, false);
                                     }
                                  } catch (Throwable var22x) {
                                     var11x = var22x;
                                     throw var22x;
                                  } finally {
                                     if (responsex != null) {
                                        if (var11x != null) {
                                           try {
                                              responsex.close();
                                           } catch (Throwable var21x) {
                                              var11x.addSuppressed(var21x);
                                           }
                                        } else {
                                           responsex.close();
                                        }
                                     }
                                  }
                               } catch (IOException var24x) {
                                  this.sendCaptureVideoDownloadNotification(downloadUrl, downloadFileName, 0L, username, false);
                               }
                            } catch (Exception var25x) {
                               var25x.printStackTrace();
                            }
                         },
                         250,
                         TimeUnit.MILLISECONDS,
                         true
                 );
         final ir.fidar.core.management.response.Response response = ir.fidar.core.management.response.Response.information("capture.convert");
         return new StreamingResponseBody() {
            public void writeTo(OutputStream outputStream) throws IOException {
               outputStream.write(CaptureCrudServiceImpl.this.objectMapper.writeValueAsString(response).getBytes());
            }
         };
      } catch (Throwable var20) {
         LOGGER.error("An unexpected error occurred while converting and downloading video of session with id '{}'", capture.getSessionId(), var20);
         throw new SystemInternalErrorException(var20);
      }
   }

   @Override
   public Optional<List<String>> loadImages(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, NoImagesCapturedFromSessionBasedOnRuleException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      JpaQuery fetchCapturedImagesOfSessionQuery = new JpaQueryBuilder()
              .select("sci.imageData")
              .from(SessionCapturedImage.class, "sci")
              .where(QueryAndFilterUtils.caseInsensitiveStringFilter("sessionId", sessionId))
              .build();
      List<String> capturedImagesOfSession = this.jpaQueryBasedReadRepository.findAll(fetchCapturedImagesOfSessionQuery, tuple -> tuple.get(0).toString());
      return Optional.of(capturedImagesOfSession);
   }

   @Override
   public Optional<List<String>> loadImages(String sessionId, String searchQuery) throws IOException, NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      List<SessionCapturedImageText> contents = this.sessionCapturedImageTextRepository.findAllBySessionId(sessionId);
      List<String> images = new ArrayList<>();
      if (contents.isEmpty()) {
         Map<File, String> contentsPerImage = new HashMap<>();
         int filePerThread = 5;
         File sessionOcrFolder = new File(String.format("%s/%s", this.ocrHostProperties.getStoragePath(), sessionId));
         if (sessionOcrFolder.exists()) {
            File[] imageFiles = sessionOcrFolder.listFiles();
            int numberOfThreads = imageFiles.length / filePerThread;
            if (imageFiles.length % filePerThread != 0) {
               numberOfThreads++;
            }

            Thread[] threads = new Thread[numberOfThreads];
            int start = 0;
            int end = start + filePerThread;
            int i = 0;

            while (true) {
               if (end > imageFiles.length) {
                  threads[i++] = new Thread(
                          new CaptureCrudServiceImpl.FetchTextFromImageTask(
                                  Arrays.copyOfRange(imageFiles, start, imageFiles.length), capture.getType(), contentsPerImage
                          )
                  );
                  break;
               }

               threads[i++] = new Thread(
                       new CaptureCrudServiceImpl.FetchTextFromImageTask(Arrays.copyOfRange(imageFiles, start, end), capture.getType(), contentsPerImage)
               );
               if (end == imageFiles.length) {
                  break;
               }

               start = end;
               end += filePerThread;
            }

            for (Thread thread : threads) {
               thread.start();

               try {
                  thread.join();
               } catch (InterruptedException var20) {
                  var20.printStackTrace();
               }
            }

            for (File imageFile : contentsPerImage.keySet()) {
               SessionCapturedImageText sessionCapturedImageText = new SessionCapturedImageText();
               sessionCapturedImageText.setSessionId(sessionId);
               sessionCapturedImageText.setContent(contentsPerImage.get(imageFile).getBytes());
               sessionCapturedImageText.setImageFileName(imageFile.getName());
               this.sessionCapturedImageTextRepository.save(sessionCapturedImageText);
               if (new String(sessionCapturedImageText.getContent()).contains(searchQuery)) {
                  images.add(this.fetchContentsOfImageAsBase64(imageFile));
               }
            }
         }
      } else {
         for (SessionCapturedImageText consoleSessionOcrText : contents) {
            if (new String(consoleSessionOcrText.getContent()).contains(searchQuery)) {
               File file = new File(String.format("%s/%s/%s", this.ocrHostProperties.getStoragePath(), sessionId, consoleSessionOcrText.getImageFileName()));
               images.add(this.fetchContentsOfImageAsBase64(file));
            }
         }
      }

      return Optional.of(images);
   }

   @Override
   public void downloadTransferredFile(String sessionId, String fileName) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, TransferredFileNotFound, IOException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      fileName = URLDecoder.decode(fileName, "UTF-8");
      String path = SessionServiceImpl.generateTransferredFilesStoragePath(capture, fileName);
      File file = new File(path);
      if (!file.exists()) {
         throw new TransferredFileNotFound();
      } else {
         HttpServletResponse response = ((ServletRequestAttributes)RequestContextHolder.getRequestAttributes()).getResponse();
         WebUtils.writeFileToResponse(response, file);
      }
   }

   @Override
   public void checkIntegrity(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, InterruptedException {
      Capture capture = Optional.ofNullable(this.captureRepository.findOneBySessionId(sessionId))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      Thread.sleep(1000L);
   }

   @Override
   public Optional<List<ListDto>> loadTransferredFiles(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      Capture capture = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.buildFetchCaptureWithAllTransferredFilesQuery(sessionId)))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      List<ListDto> transferredFilesListDtoList = new ArrayList<>();
      capture.getSessionTransferredFiles().forEach(transferredFile -> {
         SessionTransferredFileDetailsDto sessionTransferredFileDetailsDto = new SessionTransferredFileDetailsDto();
         sessionTransferredFileDetailsDto.setName(transferredFile.getName());
         sessionTransferredFileDetailsDto.setStatus(transferredFile.getStatus());
         sessionTransferredFileDetailsDto.setMode(transferredFile.getMode());
         sessionTransferredFileDetailsDto.setTime(transferredFile.getTime());
         transferredFilesListDtoList.add(sessionTransferredFileDetailsDto);
      });
      return Optional.of(transferredFilesListDtoList);
   }

   @Override
   public Optional<List<ListDto>> loadInputConstraintViolations(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      Capture capture = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.buildFetchCaptureWithAllInputConstraintViolationsQuery(sessionId)))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      List<ListDto> inputConstraintViolationListDtoList = new ArrayList<>();
      capture.getSessionInputConstraintViolationIncidents().forEach(constraintViolationIncident -> {
         SessionInputConstraintViolationIncidentDetailsDto constraintViolationIncidentDetailsDto = new SessionInputConstraintViolationIncidentDetailsDto();
         constraintViolationIncidentDetailsDto.setInput(constraintViolationIncident.getInput());
         constraintViolationIncidentDetailsDto.setRegex(constraintViolationIncident.getRegex());
         constraintViolationIncidentDetailsDto.setTime(constraintViolationIncident.getTime());
         inputConstraintViolationListDtoList.add(constraintViolationIncidentDetailsDto);
      });
      return Optional.of(inputConstraintViolationListDtoList);
   }

   @Override
   public Optional<CustomPageDto<? extends ListDto>> loadTransferredClipboards(String sessionId, Pageable pageable) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      Capture capture = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.buildFetchCaptureBySessionIdQuery(sessionId)))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, true);
      Page<CaptureTransferredClipboard> captureTransferredClipboardsPage = this.captureTransferredClipboardService
              .getAllBySpecificCapture(capture.getId(), pageable);
      CustomPageDto<CaptureTransferredClipboardListDto> customPageDto = new CustomPageDto<>();
      customPageDto.setTotalPages((long)captureTransferredClipboardsPage.getTotalPages());
      customPageDto.setTotalElements(captureTransferredClipboardsPage.getTotalElements());
      customPageDto.setContent(captureTransferredClipboardsPage.map(captureTransferredClipboard -> {
         CaptureTransferredClipboardListDto captureTransferredClipboardListDto = new CaptureTransferredClipboardListDto();
         captureTransferredClipboardListDto.setContent(captureTransferredClipboard.getContent());
         captureTransferredClipboardListDto.setTime(captureTransferredClipboard.getTime());
         captureTransferredClipboardListDto.setElapsedTime(captureTransferredClipboard.getElapsedTime());
         captureTransferredClipboardListDto.setSource(captureTransferredClipboard.getSource());
         return captureTransferredClipboardListDto;
      }).getContent());
      return Optional.of(customPageDto);
   }

   @Override
   public Optional<CustomPageDto<? extends ListDto>> loadExecutedCommands(String sessionId, Pageable pageable) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, CaptureExecutedCommandNotSupportedException {
      Capture capture = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.buildFetchCaptureBySessionIdQuery(sessionId)))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      if (!capture.getType().equals(ConnectionType.RDP) && !capture.getType().equals(ConnectionType.VNC)) {
         this.checkUserAccessibility(capture, true);
         Page<CaptureExecutedCommand> captureExecutedCommandsPage = this.captureExecutedCommandService.getAllBySpecificCapture(capture.getId(), pageable);
         CustomPageDto<CaptureExecutedCommandListDto> customPageDto = new CustomPageDto<>();
         customPageDto.setTotalPages((long)captureExecutedCommandsPage.getTotalPages());
         customPageDto.setTotalElements(captureExecutedCommandsPage.getTotalElements());
         customPageDto.setContent(captureExecutedCommandsPage.map(captureExecutedCommand -> {
            CaptureExecutedCommandListDto captureExecutedCommandListDto = new CaptureExecutedCommandListDto();
            captureExecutedCommandListDto.setContent(captureExecutedCommand.getContent());
            captureExecutedCommandListDto.setTime(captureExecutedCommand.getTime());
            captureExecutedCommandListDto.setElapsedTime((long)captureExecutedCommand.getElapsedTime().intValue());
            return captureExecutedCommandListDto;
         }).getContent());
         return Optional.of(customPageDto);
      } else {
         throw new CaptureExecutedCommandNotSupportedException();
      }
   }

   @Override
   public Optional<Flux<? extends ListDto>> streamKeyEvents(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException, FileNotFoundException {
      Capture capture = Optional.ofNullable(this.jpaQueryBasedReadRepository.findOne(this.buildFetchCaptureBySessionIdQuery(sessionId)))
              .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Capture.class)));
      this.checkUserAccessibility(capture, false);
      Bridge bridge = this.bridgeRepository.findOneByNameIgnoreCase(capture.getBridgeName());
      File file = new File(String.format("%s/%s/%s.keys", bridge.getRecordsStoragePath(), capture.getAccessRuleUuid(), capture.getSessionId()));

      try {
         BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(file.toPath()));
         byte[] buffer = new byte[2048];
         Flux<CaptureKeyEventDto> keyEventsStream = Flux.create(
                 captureKeyEventDtoFluxSink -> {
                    byte[] data = new byte[2048];
                    int dataStartPosition = 0;

                    try {
                       while (true) {
                          int numberOfReadBytes = bufferedInputStream.read(data, dataStartPosition, data.length - dataStartPosition);
                          if (numberOfReadBytes < 0) {
                             break;
                          }

                          int start = 0;
                          int end = 0;
                          int newLength = dataStartPosition + numberOfReadBytes;

                          for (int i = 0; i < newLength; i++) {
                             char c = (char)data[i];
                             if (c == '{') {
                                start = i;
                             } else if (c == '}') {
                                end = i + 1;
                                CaptureKeyEventDto captureKeyEventDto = (CaptureKeyEventDto)this.objectMapper
                                        .readValue(Arrays.copyOfRange(data, start, end), CaptureKeyEventDto.class);
                                captureKeyEventDtoFluxSink.next(captureKeyEventDto);
                             }
                          }

                          dataStartPosition = newLength - end;
                          System.arraycopy(data, end, data, 0, dataStartPosition);
                       }
                    } catch (IOException var19) {
                       throw new SystemInternalErrorException(var19);
                    } finally {
                       try {
                          bufferedInputStream.close();
                       } catch (IOException var18) {
                       }

                       captureKeyEventDtoFluxSink.complete();
                    }
                 }
         );
         return Optional.of(keyEventsStream);
      } catch (FileNotFoundException var8) {
         return null;
      } catch (Exception var9) {
         throw new SystemInternalErrorException(var9);
      }
   }

   private CaptureCrudServiceImpl.ProcessedFilters preprocessFilters(List<LinkedFilter> filters) {
      List<LinkedFilter> mainFilters = new ArrayList<>();
      Map<CaptureSpecialFilterType, LinkedFilter> specialFiltersMapper = new HashMap<>();

      for (LinkedFilter filter : filters) {
         String property = filter.getFilter().getProperty();
         CaptureSpecialFilterType targetFilter = null;

         for (CaptureSpecialFilterType specialFilter : CaptureSpecialFilterType.values()) {
            if (property.startsWith(specialFilter.getFilterProperty())) {
               targetFilter = specialFilter;
            }
         }

         if (targetFilter != null) {
            if (StringUtils.hasContent((String)filter.getFilter().getValue())) {
               String[] parts = StringUtils.split(property, ".");
               if (parts[1].equals(targetFilter.getTargetField())) {
                  filter.getFilter().setProperty(targetFilter.getTargetField());
                  specialFiltersMapper.put(targetFilter, filter);
               }
            }
         } else {
            mainFilters.add(filter);
         }
      }

      CaptureCrudServiceImpl.SpecialFilter[] specialFilters = new CaptureCrudServiceImpl.SpecialFilter[specialFiltersMapper.size()];
      int i = 0;

      for (CaptureSpecialFilterType filterType : specialFiltersMapper.keySet()) {
         specialFilters[i++] = new CaptureCrudServiceImpl.SpecialFilter(specialFiltersMapper.get(filterType), filterType);
      }

      return new CaptureCrudServiceImpl.ProcessedFilters(mainFilters, specialFilters);
   }

   private String generateLoadRecordListQuery(CaptureCrudServiceImpl.ProcessedFilters processedFilters, Pageable pageable, Sorting sorting) {
      String cteBaseName = "capture_ids";
      StringBuilder queryBuilder = new StringBuilder("WITH ")
              .append(cteBaseName)
              .append(" (id) AS (SELECT c.id FROM tb_capture c WHERE c.connection_name IN (:conNames))");
      String lastCte = cteBaseName;

      for (CaptureCrudServiceImpl.SpecialFilter specialFilter : processedFilters.getSpecialFilters()) {
         String cteName = cteBaseName + "_" + specialFilter.getFilterType().getTargetField().toLowerCase();
         queryBuilder.append(", ")
                 .append(cteName)
                 .append(" (id) AS (SELECT c.id FROM ")
                 .append(lastCte)
                 .append(" c JOIN ")
                 .append(specialFilter.getTargetTableName())
                 .append(" res ON c.id = res.capture_id WHERE LOWER(res.")
                 .append(specialFilter.getFilter().getFilter().getProperty())
                 .append(") LIKE CONCAT('%', LOWER(:")
                 .append(specialFilter.getFilterType().getTargetField())
                 .append("), '%'))");
         lastCte = cteName;
      }

      String columns = String.join(", ", LIST_COLUMNS);
      queryBuilder.append(" SELECT ")
              .append(columns)
              .append(",  COUNT(ids.id) AS TOTAL_ELEMENTS FROM tb_capture c JOIN ")
              .append(lastCte)
              .append(" ids ON c.id = ids.id");
      if (!processedFilters.getMainFilters().isEmpty()) {
         queryBuilder.append(" WHERE ")
                 .append(this.filterConversionService.convert(new FilterChainBuilder().filter(processedFilters.getMainFilters()).build()));
      }

      queryBuilder.append(" GROUP BY (ids.id) ORDER BY ")
              .append(String.format("c.%s", sorting.getProperty()))
              .append(" ")
              .append(sorting.getOrder().toString());
      if (pageable != null) {
         queryBuilder.append(" LIMIT ").append(pageable.getPageNumber() * pageable.getPageSize()).append(", ").append(pageable.getPageSize());
      }

      return queryBuilder.toString();
   }

   private CaptureListDto convertTupleToCaptureListDto(Tuple tuple) {
      CaptureListDto captureListDto = new CaptureListDto();
      captureListDto.setSessionId((String)tuple.get("session_id", String.class));
      captureListDto.setStatus(this.captureStatusConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("status", Number.class)).intValue())));
      captureListDto.setOwner((String)tuple.get("owner", String.class));
      captureListDto.setConnectionName((String)tuple.get("connection_name", String.class));
      captureListDto.setType(this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue())));
      captureListDto.setConnectionIpAddress((String)tuple.get("connection_ip_address", String.class));
      captureListDto.setStartTime(((Number)tuple.get("start_time", Number.class)).longValue());
      captureListDto.setEndTime(((Number)tuple.get("end_time", Number.class)).longValue());
      captureListDto.setBridgeName((String)tuple.get("bridge_name", String.class));
      File captureFile = new File(String.format("/records/%s/%s.mp4", tuple.get("access_rule_uuid", String.class), captureListDto.getSessionId()));
      if (captureFile.exists()) {
         captureListDto.setVideoSize(captureFile.length());
      }

      return captureListDto;
   }

   private void checkUserAccessibility(Capture capture, boolean allowNotExportable) throws InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException {
      ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus accessibilityStatus = this.captureRuleService
              .checkUserAccessibilityOverConnection(capture.getConnectionName());
      if (!accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.ACCESSIBLE)
              && (!allowNotExportable || !accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_EXPORTABLE))) {
         if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_EXPORTABLE)
                 || accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_PRIVILEGED)) {
            throw new InsufficientPrivilegeToAccessCaptureException();
         } else if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.DISABLED)) {
            throw new CaptureRuleDisabledException();
         } else if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.EXPIRED)) {
            throw new CaptureRuleExpiredException();
         }
      }
   }

   private String fetchContentsOfImageAsBase64(File file) throws IOException {
      BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(file));
      byte[] bytes = new byte[Long.valueOf(file.length()).intValue()];
      bufferedInputStream.read(bytes);
      bufferedInputStream.close();
      return new String(Base64.getEncoder().encode(bytes), "UTF-8");
   }

   private void sendCaptureVideoDownloadNotification(String url, String filename, long size, String user, boolean success) {
      String content;
      if (success) {
         Map<String, String> contentMap = new HashMap<>();
         contentMap.put("url", url);
         contentMap.put("filename", filename);
         contentMap.put("size", String.valueOf(size));

         try {
            content = this.objectMapper.writeValueAsString(contentMap);
         } catch (JsonProcessingException var11) {
            return;
         }
      } else {
         content = "FAILED";
      }

      try {
         this.notificationService
                 .broadCastMessage(
                         new ServerEvent(ServerEventType.DOWNLOAD, content, SystemConstantsAndDefaults.Security.SYSTEM_USER_AUTHENTICATION.getName()),
                         Collections.singleton(user)
                 );
      } catch (SseConnectionBrokenException var10) {
      }
   }

   private JpaQuery<Capture> buildFetchCaptureWithAllTransferredFilesQuery(String sessionId) {
      return new JpaQueryBuilder()
              .from(Capture.class, "c")
              .leftJoin("sessionTransferredFiles", "stf")
              .fetch()
              .where(QueryAndFilterUtils.caseInsensitiveStringFilter("sessionId", sessionId))
              .build();
   }

   private JpaQuery<Capture> buildFetchCaptureWithAllInputConstraintViolationsQuery(String sessionId) {
      return new JpaQueryBuilder()
              .from(Capture.class, "c")
              .leftJoin("sessionInputConstraintViolationIncidents", "sicvi")
              .fetch()
              .where(QueryAndFilterUtils.caseInsensitiveStringFilter("sessionId", sessionId))
              .build();
   }

   private JpaQuery<Capture> buildFetchCaptureBySessionIdQuery(String sessionId) {
      return new JpaQueryBuilder().from(Capture.class, "c").where(QueryAndFilterUtils.caseInsensitiveStringFilter("sessionId", sessionId)).build();
   }

   private class FetchTextFromImageTask implements Runnable {
      private final String COMMAND_FORMAT = "tesseract %s stdout -l %s -psm %d";
      private File[] files;
      private ConnectionType type;
      private Map<File, String> result;

      public FetchTextFromImageTask(File[] files, ConnectionType type, Map<File, String> result) {
         this.files = files;
         this.type = type;
         this.result = result;
      }

      @Override
      public void run() {
         for (File file : this.files) {
            try {
               String content = CaptureCrudServiceImpl.this.ocrHttpClient
                       .sendExtractionRequest(
                               Files.readAllBytes(file.toPath()),
                               !this.type.equals(ConnectionType.SSH) && !this.type.equals(ConnectionType.TELNET) ? 4 : 6,
                               OcrHttpClient.Dataset.BEST,
                               1
                       );
               if (content != null) {
                  synchronized (this.result) {
                     this.result.put(file, content);
                  }
               }
            } catch (IOException var9) {
            }
         }
      }
   }

   private static class ProcessedFilters {
      private final List<LinkedFilter> mainFilters;
      private final CaptureCrudServiceImpl.SpecialFilter[] specialFilters;

      private ProcessedFilters(List<LinkedFilter> mainFilters, CaptureCrudServiceImpl.SpecialFilter... specialFilters) {
         this.mainFilters = mainFilters;
         this.specialFilters = specialFilters;
      }

      public List<LinkedFilter> getMainFilters() {
         return this.mainFilters;
      }

      public CaptureCrudServiceImpl.SpecialFilter[] getSpecialFilters() {
         return this.specialFilters;
      }

      public boolean containsSpecialFilter() {
         return this.specialFilters != null && this.specialFilters.length > 0;
      }
   }

   private static class SpecialFilter {
      private final LinkedFilter filter;
      private final CaptureSpecialFilterType filterType;
      private final String targetTableName;

      private SpecialFilter(LinkedFilter filter, CaptureSpecialFilterType filterType) {
         this.filter = filter;
         this.filterType = filterType;
         this.targetTableName = ((Table)filterType.getTargetEntity().getAnnotation(Table.class)).name();
      }

      public LinkedFilter getFilter() {
         return this.filter;
      }

      public CaptureSpecialFilterType getFilterType() {
         return this.filterType;
      }

      public String getTargetTableName() {
         return this.targetTableName;
      }
   }
}
