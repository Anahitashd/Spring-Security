package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.domain.dto.crud.ListDto;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.security.exception.AuthorizationException;
import ir.fidar.core.security.exception.UnauthorizedException;
import ir.fidar.core.service.impl.generic.GlobalCommonServiceImpl;
import ir.fidar.core.util.HttpMimeType;
import ir.fidar.core.util.PagingUtil;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.WebUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.da.repository.TransparentCaptureRepository;
import ir.fidar.pam.domain.dto.capture.TransparentCaptureListDto;
import ir.fidar.pam.domain.dto.capture.TransparentCaptureRegistrationDto;
import ir.fidar.pam.domain.dto.connection.TransparentConnectionPortMappingDto;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.session.TransparentCapture;
import ir.fidar.pam.domain.type.CaptureStatus;
import ir.fidar.pam.exception.capturerule.CaptureRuleDisabledException;
import ir.fidar.pam.exception.capturerule.CaptureRuleExpiredException;
import ir.fidar.pam.exception.connection.NoCaptureRuleIsFoundForConnectionException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessCaptureException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.TransparentCaptureService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@Service
public class TransparentCaptureServiceImpl extends GlobalCommonServiceImpl<TransparentCapture> implements TransparentCaptureService {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String STORAGE_PATH = "/records/transparent";
   private static final String DOWNLOAD_IDENTIFIER_PARAMETER = "id";
   private static final String DOWNLOAD_USERNAME_PARAMETER = "un";
   private static final String AUTH_TOKEN = "f7fe4d8d-b9bd-47f8-942a-93741bbc204a";
   private static final ConcurrentMap<String, String> USER_DOWNLOAD_IDENTIFIER_MAP = new ConcurrentHashMap<>();
   private final TransparentCaptureRepository transparentCaptureRepository;
   private final ConnectionService connectionService;
   private final CaptureRuleService captureRuleService;
   private final AsyncTaskExecutor asyncTaskExecutor;

   public TransparentCaptureServiceImpl(
      TransparentCaptureRepository transparentCaptureRepository,
      ConnectionService connectionService,
      CaptureRuleService captureRuleService,
      AsyncTaskExecutor asyncTaskExecutor
   ) {
      super(transparentCaptureRepository);
      this.transparentCaptureRepository = transparentCaptureRepository;
      this.connectionService = connectionService;
      this.captureRuleService = captureRuleService;
      this.asyncTaskExecutor = asyncTaskExecutor;
   }

   @Override
   public Optional<List<? extends ListDto>> load(List<LinkedFilter> filters, Sorting sorting) {
      Collection<String> connectionNames = this.connectionService.getAllConnectionsThatCurrentUserCanReviewTheirCaptures();
      if (connectionNames.isEmpty()) {
         return Optional.of(new ArrayList<>());
      } else {
         filters.add(new FilterBuilder().list("connection_name").in(connectionNames).buildSingle());
         NativeQuery<TransparentCapture> nativeQuery = new NativeQueryBuilder()
            .from(TransparentCapture.class, "tc")
            .where(new FilterChainBuilder().filter(filters).build())
            .orderBy(sorting)
            .build();
         List<TransparentCapture> transparentCaptures = this.nativeQueryBasedReadRepository.findAll(nativeQuery);
         List<TransparentCaptureListDto> transparentCaptureListDtoList = transparentCaptures.stream()
            .map(this::convertTransparentCaptureToListDto)
            .collect(Collectors.toList());
         return Optional.of(transparentCaptureListDtoList);
      }
   }

   @Override
   public Optional<CustomPageDto<? extends ListDto>> load(List<LinkedFilter> filters, Pageable pageable, Sorting sorting) throws Exception {
      Collection<String> connectionNames = this.connectionService.getAllConnectionsThatCurrentUserCanReviewTheirCaptures();
      if (connectionNames.isEmpty()) {
         return Optional.of(PagingUtil.emptyCustomPage());
      } else {
         filters.add(new FilterBuilder().list("connection_name").in(connectionNames).buildSingle());
         NativePaginationQuery<TransparentCapture> nativeQuery = (NativePaginationQuery<TransparentCapture>)new NativePaginationQueryBuilder()
            .page(pageable)
            .from(TransparentCapture.class, "tc")
            .where(new FilterChainBuilder().filter(filters).build())
            .orderBy(sorting)
            .build();
         CustomPageDto<TransparentCapture> transparentCapturesPage = this.nativeQueryBasedReadRepository.find(nativeQuery, pageable);
         List<TransparentCaptureListDto> transparentCaptureListDtoList = transparentCapturesPage.getContent()
            .stream()
            .map(this::convertTransparentCaptureToListDto)
            .collect(Collectors.toList());
         CustomPageDto<TransparentCaptureListDto> transparentCaptureListDtoPage = new CustomPageDto<>(
            transparentCaptureListDtoList, transparentCapturesPage.getTotalElements(), transparentCapturesPage.getTotalPages()
         );
         return Optional.of(transparentCaptureListDtoPage);
      }
   }

   @Transactional
   @Override
   public String registerNewSession(TransparentCaptureRegistrationDto transparentCaptureRegistrationDto, String token) {
      this.authenticate(token);
      LOGGER.debug(
         Markers.SESSION,
         "About to register new transparent session to '{}'",
         String.format("%s:%d", transparentCaptureRegistrationDto.getConnectionIpAddress(), transparentCaptureRegistrationDto.getConnectionPort())
      );
      Connection connection = this.connectionService
         .getOneByHostInfo(
            transparentCaptureRegistrationDto.getConnectionType(),
            transparentCaptureRegistrationDto.getConnectionIpAddress(),
            transparentCaptureRegistrationDto.getConnectionPort(),
            true
         );

      String uuid;
      do {
         uuid = UUID.randomUUID().toString();
      } while (this.transparentCaptureRepository.existsByUuidGlobally(uuid));

      TransparentCapture transparentCapture = new TransparentCapture();
      transparentCapture.setSessionId(uuid);
      transparentCapture.setStartTime(Instant.now().getEpochSecond());
      transparentCapture.setEndTime(0L);
      transparentCapture.setStatus(CaptureStatus.LIVE);
      transparentCapture.setConnectionType(connection.getType());
      transparentCapture.setConnectionName(connection.getName());
      transparentCapture.setConnectionIpAddress(connection.getIpAddress());
      transparentCapture.setConnectionPort(connection.getPort());
      transparentCapture.setClientIpAddress(transparentCaptureRegistrationDto.getClientIpAddress());
      transparentCapture.setClientPort(transparentCaptureRegistrationDto.getClientPort());
      transparentCapture.setClientUsername(transparentCaptureRegistrationDto.getClientUsername());
      transparentCapture.setClientPassword(transparentCaptureRegistrationDto.getClientPassword());
      transparentCapture.setClientDomain(transparentCaptureRegistrationDto.getClientDomain());
      transparentCapture.setClientHostname(transparentCaptureRegistrationDto.getClientHostname());
      transparentCapture.setClientCertificateName(transparentCaptureRegistrationDto.getClientCertificateName());
      this.transparentCaptureRepository.save(transparentCapture);
      LOGGER.info(
         Markers.SESSION,
         "New '{}' transparent session is established to connection '{}', [address: {}]",
         transparentCapture.getConnectionType().toString(),
         transparentCapture.getConnectionName(),
         String.format("%s:%d", transparentCapture.getConnectionIpAddress(), transparentCapture.getConnectionPort())
      );
      return uuid;
   }

   @Transactional
   @Override
   public void closeSession(String uuid, String token) {
      this.authenticate(token);
      TransparentCapture transparentCapture = Optional.ofNullable(this.transparentCaptureRepository.findOneBySessionId(uuid))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(TransparentCapture.class)));
      transparentCapture.setStatus(CaptureStatus.CLOSED);
      transparentCapture.setEndTime(Instant.now().getEpochSecond());
   }

   @Override
   public TransparentConnectionPortMappingDto loadConnectionMappedToPort(int port, String token) {
      this.authenticate(token);
      Connection transparentConnection = this.connectionService.getOneByTransparentPort(port);
      TransparentConnectionPortMappingDto portMappingDto = new TransparentConnectionPortMappingDto();
      portMappingDto.setIpAddress(transparentConnection.getIpAddress());
      portMappingDto.setPort(transparentConnection.getPort());
      portMappingDto.setListeningPort(transparentConnection.getTransparentPort());
      return portMappingDto;
   }

   @Override
   public String generateDownloadIdentifier(String sessionId) throws NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      TransparentCapture transparentCapture = Optional.ofNullable(this.transparentCaptureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(TransparentCapture.class)));
      this.checkUserAccessibility(transparentCapture);
      String username = this.authorizationService.getCurrentUserInfo().getUsername();
      USER_DOWNLOAD_IDENTIFIER_MAP.remove(username);

      String id;
      do {
         id = UUID.randomUUID().toString();
      } while (USER_DOWNLOAD_IDENTIFIER_MAP.containsValue(id));

      USER_DOWNLOAD_IDENTIFIER_MAP.put(username, id);
      this.asyncTaskExecutor.executeTask(() -> USER_DOWNLOAD_IDENTIFIER_MAP.remove(username), 1, TimeUnit.HOURS);
      return id;
   }

   @Override
   public FileSystemResource playVideo(String sessionId, String username, String id) throws FileNotFoundException {
      if (StringUtils.hasContent(id) && StringUtils.hasContent(username) && USER_DOWNLOAD_IDENTIFIER_MAP.containsKey(username)) {
         TransparentCapture transparentCapture = Optional.ofNullable(this.transparentCaptureRepository.findOneBySessionId(sessionId))
            .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(TransparentCapture.class)));
         String videoPath = this.getRecordedVideoPath(transparentCapture);
         File file = new File(videoPath);
         if (!file.exists()) {
            throw new FileNotFoundException();
         } else {
            return new FileSystemResource(file);
         }
      } else {
         throw new AuthorizationException() {
            @Override
            public String getCode() {
               return "access_denied";
            }
         };
      }
   }

   @Override
   public StreamingResponseBody downloadVideo(String sessionId, HttpServletResponse httpServletResponse) throws FileNotFoundException, NoCaptureRuleIsFoundForConnectionException, CaptureRuleExpiredException, CaptureRuleDisabledException, InsufficientPrivilegeToAccessCaptureException {
      TransparentCapture transparentCapture = Optional.ofNullable(this.transparentCaptureRepository.findOneBySessionId(sessionId))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(TransparentCapture.class)));
      this.checkUserAccessibility(transparentCapture);
      File file = this.getRecordedVideoFile(transparentCapture);

      try {
         if (transparentCapture.getStatus().equals(CaptureStatus.CLOSED)) {
            return WebUtils.streamFile(httpServletResponse, file, HttpMimeType.VIDEO_MP4.getValue());
         } else {
            httpServletResponse.setContentType(HttpMimeType.VIDEO_MP4.getValue());
            return outputStream -> {
               BufferedInputStream inputStream = new BufferedInputStream(new FileInputStream(file));
               byte[] buffer = new byte[8192];
               long count = 0L;

               while (count < 20L) {
                  int readBytes = inputStream.read(buffer);
                  if (readBytes == -1) {
                     try {
                        Thread.sleep(1500L);
                     } catch (InterruptedException var8) {
                        break;
                     }

                     count++;
                  } else {
                     outputStream.write(Arrays.copyOfRange(buffer, 0, readBytes));
                  }
               }
            };
         }
      } catch (java.io.FileNotFoundException var6) {
         throw new FileNotFoundException();
      } catch (Exception var7) {
         throw new SystemInternalErrorException(var7);
      }
   }

   private void authenticate(String token) {
      if (!"f7fe4d8d-b9bd-47f8-942a-93741bbc204a".equalsIgnoreCase(token)) {
         throw new UnauthorizedException() {
            @Override
            public int getMappedHttpCode() {
               return 403;
            }
         };
      }
   }

   private TransparentCaptureListDto convertTransparentCaptureToListDto(TransparentCapture transparentCapture) {
      TransparentCaptureListDto transparentCaptureListDto = new TransparentCaptureListDto();
      transparentCaptureListDto.setSessionId(transparentCapture.getSessionId());
      transparentCaptureListDto.setStatus(transparentCapture.getStatus());
      transparentCaptureListDto.setStartTime(transparentCapture.getStartTime());
      transparentCaptureListDto.setEndTime(transparentCapture.getEndTime());
      transparentCaptureListDto.setConnectionType(transparentCapture.getConnectionType());
      transparentCaptureListDto.setConnectionName(transparentCapture.getConnectionName());
      transparentCaptureListDto.setConnectionIpAddress(transparentCapture.getConnectionIpAddress());
      transparentCaptureListDto.setConnectionPort(transparentCapture.getConnectionPort());
      transparentCaptureListDto.setClientIpAddress(transparentCapture.getClientIpAddress());
      transparentCaptureListDto.setClientPort(transparentCapture.getClientPort());
      transparentCaptureListDto.setClientUsername(transparentCapture.getClientUsername());
      transparentCaptureListDto.setClientPassword(transparentCapture.getClientPassword());
      transparentCaptureListDto.setClientDomain(transparentCapture.getClientDomain());
      transparentCaptureListDto.setClientHostname(transparentCapture.getClientHostname());
      transparentCaptureListDto.setClientCertificateName(transparentCapture.getClientCertificateName());
      File file = new File(String.format("%s/%s.mp4", "/records/transparent", transparentCapture.getSessionId()));
      if (file.exists()) {
         transparentCaptureListDto.setVideoSize(file.length());
      }

      return transparentCaptureListDto;
   }

   private void checkUserAccessibility(TransparentCapture transparentCapture) throws InsufficientPrivilegeToAccessCaptureException, CaptureRuleDisabledException, CaptureRuleExpiredException, NoCaptureRuleIsFoundForConnectionException {
      ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus accessibilityStatus = this.captureRuleService
         .checkUserAccessibilityOverConnection(transparentCapture.getConnectionName());
      if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_EXPORTABLE)
         || accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.NOT_PRIVILEGED)) {
         throw new InsufficientPrivilegeToAccessCaptureException();
      } else if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.DISABLED)) {
         throw new CaptureRuleDisabledException();
      } else if (accessibilityStatus.equals(ir.fidar.pam.service.CaptureRuleService.AccessibilityStatus.EXPIRED)) {
         throw new CaptureRuleExpiredException();
      }
   }

   private String getRecordedVideoPath(TransparentCapture transparentCapture) {
      return String.format("%s/%s.mp4", "/records/transparent", transparentCapture.getSessionId());
   }

   private File getRecordedVideoFile(TransparentCapture transparentCapture) {
      return new File(this.getRecordedVideoPath(transparentCapture));
   }
}
