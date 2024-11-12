package ir.fidar.pam.service.impl.report;

import ir.fidar.core.da.core.context.RepositoryContextManager;
import ir.fidar.core.da.core.query.NativePaginationQuery;
import ir.fidar.core.da.core.query.NativeQuery;
import ir.fidar.core.da.core.query.Sorting;
import ir.fidar.core.da.core.query.builder.NativePaginationQueryBuilder;
import ir.fidar.core.da.core.query.builder.NativeQueryBuilder;
import ir.fidar.core.da.core.repository.NativeQueryBasedReadRepository;
import ir.fidar.core.domain.dto.CustomPageDto;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.filter.FilterBuilder;
import ir.fidar.core.util.filter.FilterChainBuilder;
import ir.fidar.core.util.filter.QueryAndFilterUtils;
import ir.fidar.core.util.filter.chain.LinkedFilter;
import ir.fidar.pam.domain.dto.report.useractivity.UserAuthenticationAttemptCountDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserConstraintViolationsOverRemoteSessionDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserRemoteSessionDurationDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserSessionCountPerTypeDto;
import ir.fidar.pam.domain.dto.report.useractivity.UserTransferredFilesOverRemoteSessionDto;
import ir.fidar.pam.domain.model.session.Capture;
import ir.fidar.pam.domain.model.session.SessionInputConstraintViolationIncident;
import ir.fidar.pam.domain.model.session.SessionTransferredFile;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.TimeUnit;
import ir.fidar.pam.domain.util.converter.attribbute.SessionTransferredFileModeConverter;
import ir.fidar.pam.domain.util.converter.attribbute.SessionTransferredFileStatusConverter;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import ir.fidar.pam.service.UserService;
import ir.fidar.pam.service.report.UserActivityReportService;
import java.time.Month;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoField;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import jakarta.persistence.Tuple;
import org.springframework.stereotype.Service;

@Service
public class UserActivityReportServiceImpl implements UserActivityReportService {
   private static final String AUTHENTICATION_ATTEMPTS_STATEMENT = "SELECT la.loginTime, la.success FROM LoginAttempt la WHERE la.loginTime >= :startTime ORDER BY la.loginTime ASC ";
   private static final String USER_AUTHENTICATION_ATTEMPTS_STATEMENT = "SELECT la.loginTime, la.success FROM LoginAttempt la WHERE la.loginTime >= :startTime AND la.username = :username ORDER BY la.loginTime ASC ";
   private final UserService userService;
   private final NativeQueryBasedReadRepository readRepository;
   private final ConnectionTypeConverter connectionTypeConverter;
   private final SessionTransferredFileStatusConverter sessionTransferredFileStatusConverter;
   private final SessionTransferredFileModeConverter sessionTransferredFileModeConverter;

   public UserActivityReportServiceImpl(UserService userService, NativeQueryBasedReadRepository readRepository) {
      this.userService = userService;
      this.readRepository = readRepository;
      this.connectionTypeConverter = new ConnectionTypeConverter();
      this.sessionTransferredFileStatusConverter = new SessionTransferredFileStatusConverter();
      this.sessionTransferredFileModeConverter = new SessionTransferredFileModeConverter();
   }

   @Override
   public List<UserAuthenticationAttemptCountDto> retrieveAuthenticationAttemptsInLastUnitTime(TimeUnit timeUnit, int count) {
      long startTime = this.getTomorrowStartDayTimeAsEpochSeconds();
      long baseTime = (long)this.getTotalTimeInSeconds(timeUnit, count);
      return this.fetchUnitBasedLoginAttemptsAndConvertToDto(
         "SELECT la.loginTime, la.success FROM LoginAttempt la WHERE la.loginTime >= :startTime ORDER BY la.loginTime ASC ",
         Collections.singletonMap("startTime", startTime - baseTime),
         timeUnit,
         count
      );
   }

   @Override
   public List<UserAuthenticationAttemptCountDto> retrieveAuthenticationAttemptsInLastUnitTime(String username, TimeUnit timeUnit, int count) {
      long startTime = this.getTomorrowStartDayTimeAsEpochSeconds();
      long baseTime = (long)this.getTotalTimeInSeconds(timeUnit, count);
      Map<String, Object> params = new HashMap<>(2);
      params.put("startTime", startTime - baseTime);
      params.put("username", username);
      return this.fetchUnitBasedLoginAttemptsAndConvertToDto(
         "SELECT la.loginTime, la.success FROM LoginAttempt la WHERE la.loginTime >= :startTime AND la.username = :username ORDER BY la.loginTime ASC ",
         params,
         timeUnit,
         count
      );
   }

   @Override
   public UserAuthenticationAttemptCountDto retrieveTotalAuthenticationAttempts(String username) {
      this.userService.getOne(username);
      String statement = "SELECT la.success, COUNT(la.username) AS C FROM LoginAttempt la WHERE la.username = :username GROUP BY la.success";
      List<Tuple> tuples = this.executeQuery(statement, Collections.singletonMap("username", username));
      UserAuthenticationAttemptCountDto userAuthenticationAttemptCountDto = new UserAuthenticationAttemptCountDto();

      for (Tuple tuple : tuples) {
         if ((Boolean)tuple.get(0, Boolean.class)) {
            userAuthenticationAttemptCountDto.setSuccessfulAttempts(((Number)tuple.get(1, Number.class)).intValue());
         } else {
            userAuthenticationAttemptCountDto.setFailedAttempts(((Number)tuple.get(1, Number.class)).intValue());
         }
      }

      return userAuthenticationAttemptCountDto;
   }

   @Override
   public UserSessionCountPerTypeDto retrieveSessionCountsPerType(String username) {
      this.userService.getOne(username);
      String statement = "SELECT c.type, COUNT(c.sessionId) FROM Capture c WHERE c.owner = :username GROUP BY c.type";
      List<Tuple> tuples = this.executeQuery(statement, Collections.singletonMap("username", username));
      UserSessionCountPerTypeDto userSessionCountPerTypeDto = new UserSessionCountPerTypeDto();

      for (Tuple tuple : tuples) {
         ConnectionType connectionType = (ConnectionType)tuple.get(0, ConnectionType.class);
         int count = ((Number)tuple.get(1, Number.class)).intValue();
         switch (connectionType) {
            case SSH:
               userSessionCountPerTypeDto.setSshSessions(count);
               break;
            case RDP:
               userSessionCountPerTypeDto.setRdpSessions(count);
               break;
            case VNC:
               userSessionCountPerTypeDto.setVncSessions(count);
               break;
            case TELNET:
               userSessionCountPerTypeDto.setTelnetSessions(count);
         }
      }

      return userSessionCountPerTypeDto;
   }

   @Override
   public List<UserSessionCountPerTypeDto> retrieveSessionCountsPerTypeBaseOnTime(String username, TimeUnit timeUnit, int count) {
      this.userService.getOne(username);
      long startTime = this.getTomorrowStartDayTimeAsEpochSeconds();
      long baseTime = (long)this.getTotalTimeInSeconds(timeUnit, count);
      String statement = "SELECT c.startTime, c.type FROM Capture c WHERE c.owner = :username AND c.startTime >= :startTime ORDER BY c.startTime ASC";
      Map<String, Object> params = new HashMap<>(2);
      params.put("startTime", startTime - baseTime);
      params.put("username", username);
      List<Tuple> tuples = this.executeQuery(statement, params);
      List<UserSessionCountPerTypeDto> timeBasedUserSessionCountPerTypeDtoList = new ArrayList<>(count);
      long nowInSeconds = this.getTomorrowStartDayTimeAsEpochSeconds();
      if (timeUnit.equals(TimeUnit.MONTH)) {
         int i = tuples.size() - 1;
         int currentMonth = this.getCurrentMonth();

         for (long highLimit = nowInSeconds; count >= 0; count--) {
            if (currentMonth < 1) {
               currentMonth = 12;
            }

            long currentMonthDaysInSeconds = (long)(Month.of(currentMonth).maxLength() * 24 * 3600);
            long lowLimit = highLimit - currentMonthDaysInSeconds;
            int sshSessions = 0;
            int rdpSessions = 0;
            int vncSessions = 0;

            int telnetSessions;
            for (telnetSessions = 0; i >= 0; i--) {
               Tuple tuple = tuples.get(i);
               int time = ((Number)tuple.get(0, Number.class)).intValue();
               if ((long)time >= highLimit || (long)time < lowLimit) {
                  break;
               }

               ConnectionType type = (ConnectionType)tuple.get(1, ConnectionType.class);
               switch (type) {
                  case SSH:
                     sshSessions++;
                     break;
                  case RDP:
                     rdpSessions++;
                     break;
                  case VNC:
                     vncSessions++;
                     break;
                  case TELNET:
                     telnetSessions++;
               }
            }

            UserSessionCountPerTypeDto userSessionCountPerTypeDto = new UserSessionCountPerTypeDto();
            userSessionCountPerTypeDto.setSshSessions(sshSessions);
            userSessionCountPerTypeDto.setRdpSessions(rdpSessions);
            userSessionCountPerTypeDto.setVncSessions(vncSessions);
            userSessionCountPerTypeDto.setTelnetSessions(telnetSessions);
            timeBasedUserSessionCountPerTypeDtoList.add(userSessionCountPerTypeDto);
            highLimit = lowLimit;
            currentMonth--;
         }

         Collections.reverse(timeBasedUserSessionCountPerTypeDtoList);
      } else {
         long unitBaseTimeInSeconds = (long)this.getUnitTimeInSeconds(timeUnit);
         long lowLimit = nowInSeconds - unitBaseTimeInSeconds * (long)count;

         for (int i = 0; count > 0; count--) {
            long highLimit = lowLimit + unitBaseTimeInSeconds;
            int sshSessions = 0;
            int rdpSessions = 0;
            int vncSessions = 0;

            int telnetSessions;
            for (telnetSessions = 0; i < tuples.size(); i++) {
               Tuple tuple = tuples.get(i);
               int time = ((Number)tuple.get(0, Number.class)).intValue();
               if ((long)time >= highLimit || (long)time < lowLimit) {
                  break;
               }

               ConnectionType type = (ConnectionType)tuple.get(1, ConnectionType.class);
               switch (type) {
                  case SSH:
                     sshSessions++;
                     break;
                  case RDP:
                     rdpSessions++;
                     break;
                  case VNC:
                     vncSessions++;
                     break;
                  case TELNET:
                     telnetSessions++;
               }
            }

            UserSessionCountPerTypeDto userSessionCountPerTypeDto = new UserSessionCountPerTypeDto();
            userSessionCountPerTypeDto.setSshSessions(sshSessions);
            userSessionCountPerTypeDto.setRdpSessions(rdpSessions);
            userSessionCountPerTypeDto.setVncSessions(vncSessions);
            userSessionCountPerTypeDto.setTelnetSessions(telnetSessions);
            timeBasedUserSessionCountPerTypeDtoList.add(userSessionCountPerTypeDto);
            lowLimit = highLimit;
         }
      }

      return timeBasedUserSessionCountPerTypeDtoList;
   }

   @Override
   public List<UserTransferredFilesOverRemoteSessionDto> retrieveUserTransferredFilesOverRemoteSessions(String username) {
      this.userService.getOne(username);
      NativeQuery query = new NativeQueryBuilder()
         .select("c.connectionName", "c.connectionIpAddress", "c.type", "stf.name", "stf.time", "stf.mode", "stf.status")
         .from(Capture.class, "c")
         .join(SessionTransferredFile.class, "stf")
         .on("id", "capture_id")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("owner", username))
         .build();
      return this.readRepository
         .findAll(
            query,
            tuple -> {
               UserTransferredFilesOverRemoteSessionDto userTransferredFilesOverRemoteSessionDto = new UserTransferredFilesOverRemoteSessionDto();
               userTransferredFilesOverRemoteSessionDto.setConnectionName((String)tuple.get("connectionName", String.class));
               userTransferredFilesOverRemoteSessionDto.setConnectionIpAddress((String)tuple.get("connectionIpAddress", String.class));
               userTransferredFilesOverRemoteSessionDto.setConnectionType(
                  this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue()))
               );
               userTransferredFilesOverRemoteSessionDto.setFileName((String)tuple.get("name", String.class));
               userTransferredFilesOverRemoteSessionDto.setTime((long)((Number)tuple.get("time", Number.class)).intValue());
               userTransferredFilesOverRemoteSessionDto.setMode(
                  this.sessionTransferredFileModeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("mode", Number.class)).intValue()))
               );
               userTransferredFilesOverRemoteSessionDto.setStatus(
                  this.sessionTransferredFileStatusConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("status", Number.class)).intValue()))
               );
               return userTransferredFilesOverRemoteSessionDto;
            }
         );
   }

   @Override
   public List<UserConstraintViolationsOverRemoteSessionDto> retrieveUserConstraintViolationsOverRemoteSessions(String username) {
      this.userService.getOne(username);
      NativeQuery query = new NativeQueryBuilder()
         .select("c.connectionName", "c.connectionIpAddress", "c.type", "sicvi.input", "sicvi.regex", "sicvi.time")
         .from(Capture.class, "c")
         .join(SessionInputConstraintViolationIncident.class, "sicvi")
         .on("id", "capture_id")
         .where(QueryAndFilterUtils.caseInsensitiveStringFilter("owner", username))
         .build();
      return this.readRepository
         .findAll(
            query,
            tuple -> {
               UserConstraintViolationsOverRemoteSessionDto userConstraintViolationsOverRemoteSessionDto = new UserConstraintViolationsOverRemoteSessionDto();
               userConstraintViolationsOverRemoteSessionDto.setConnectionName((String)tuple.get("connectionName", String.class));
               userConstraintViolationsOverRemoteSessionDto.setConnectionIpAddress((String)tuple.get("connectionIpAddress", String.class));
               userConstraintViolationsOverRemoteSessionDto.setConnectionType(
                  this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue()))
               );
               userConstraintViolationsOverRemoteSessionDto.setInput((String)tuple.get("input", String.class));
               userConstraintViolationsOverRemoteSessionDto.setRegex((String)tuple.get("regex", String.class));
               userConstraintViolationsOverRemoteSessionDto.setTime((long)((Number)tuple.get("time", Number.class)).intValue());
               return userConstraintViolationsOverRemoteSessionDto;
            }
         );
   }

   @Override
   public List<UserRemoteSessionDurationDto> retrieveLastNRemoteSessionDuration(int count) {
      return this.fetchLastRemoteSessionDurations(null, count);
   }

   @Override
   public List<UserRemoteSessionDurationDto> retrieveUserLastNRemoteSessionDuration(String username, int count) {
      this.userService.getOne(username);
      return this.fetchLastRemoteSessionDurations(username, count);
   }

   private List<Tuple> executeQuery(String statement, Map<String, Object> parameters) {
      EntityManager entityManager = RepositoryContextManager.getUnderlyingEntityManager();
      Query query = entityManager.createQuery(statement, Tuple.class).setHint("org.hibernate.readOnly", Boolean.TRUE);
      if (parameters != null) {
         for (Entry<String, Object> parameterKeyValue : parameters.entrySet()) {
            query.setParameter(parameterKeyValue.getKey(), parameterKeyValue.getValue());
         }
      }

      return query.getResultList();
   }

   private List<UserAuthenticationAttemptCountDto> fetchUnitBasedLoginAttemptsAndConvertToDto(
      String statement, Map<String, Object> parameters, TimeUnit timeUnit, int count
   ) {
      List<Tuple> tuples = this.executeQuery(statement, parameters);
      List<UserAuthenticationAttemptCountDto> timeBasedUserAuthenticationAttemptCountDtoList = new ArrayList<>(count);
      long unitBaseTimeInSeconds = (long)this.getUnitTimeInSeconds(timeUnit);
      long nowInSeconds = this.getTomorrowStartDayTimeAsEpochSeconds();
      if (timeUnit.equals(TimeUnit.MONTH)) {
         int i = tuples.size() - 1;
         int currentMonth = this.getCurrentMonth();

         for (long highLimit = nowInSeconds; count >= 0; count--) {
            if (currentMonth < 1) {
               currentMonth = 12;
            }

            long currentMonthDaysInSeconds = (long)(Month.of(currentMonth).maxLength() * 24 * 3600);
            long lowLimit = highLimit - currentMonthDaysInSeconds;
            int successfulAttempts = 0;

            int failedAttempts;
            for (failedAttempts = 0; i >= 0; i--) {
               Tuple tuple = tuples.get(i);
               int time = ((Number)tuple.get(0, Number.class)).intValue();
               if ((long)time >= highLimit || (long)time < lowLimit) {
                  break;
               }

               if ((Boolean)tuple.get(1, Boolean.class)) {
                  successfulAttempts++;
               } else {
                  failedAttempts++;
               }
            }

            UserAuthenticationAttemptCountDto userAuthenticationAttemptCountDto = new UserAuthenticationAttemptCountDto();
            userAuthenticationAttemptCountDto.setSuccessfulAttempts(successfulAttempts);
            userAuthenticationAttemptCountDto.setFailedAttempts(failedAttempts);
            timeBasedUserAuthenticationAttemptCountDtoList.add(userAuthenticationAttemptCountDto);
            highLimit = lowLimit;
            currentMonth--;
         }

         Collections.reverse(timeBasedUserAuthenticationAttemptCountDtoList);
      } else {
         int i = 0;

         for (long lowLimit = nowInSeconds - unitBaseTimeInSeconds * (long)count; count > 0; count--) {
            long highLimit = lowLimit + unitBaseTimeInSeconds;
            int successfulAttempts = 0;

            int failedAttempts;
            for (failedAttempts = 0; i < tuples.size(); i++) {
               Tuple tuplex = tuples.get(i);
               int timex = ((Number)tuplex.get(0, Number.class)).intValue();
               if ((long)timex >= highLimit || (long)timex < lowLimit) {
                  break;
               }

               if ((Boolean)tuplex.get(1, Boolean.class)) {
                  successfulAttempts++;
               } else {
                  failedAttempts++;
               }
            }

            UserAuthenticationAttemptCountDto unitBasedUserAuthenticationAttemptCountDto = new UserAuthenticationAttemptCountDto();
            unitBasedUserAuthenticationAttemptCountDto.setSuccessfulAttempts(successfulAttempts);
            unitBasedUserAuthenticationAttemptCountDto.setFailedAttempts(failedAttempts);
            timeBasedUserAuthenticationAttemptCountDtoList.add(unitBasedUserAuthenticationAttemptCountDto);
            lowLimit = highLimit;
         }
      }

      return timeBasedUserAuthenticationAttemptCountDtoList;
   }

   private List<UserRemoteSessionDurationDto> fetchLastRemoteSessionDurations(String username, int count) {
      List<LinkedFilter> filters = new FilterBuilder().number("endTime").gt(0).build();
      if (StringUtils.hasContent(username)) {
         filters.add(new FilterBuilder().string("owner").eq(username).ignoreCaseSensitive().buildSingle());
      }

      NativePaginationQuery query = (NativePaginationQuery)new NativePaginationQueryBuilder()
         .page(0, count)
         .select("c.type", "c.connectionIpAddress", "c.startTime", "c.endTime")
         .from(Capture.class, "c")
         .where(new FilterChainBuilder().filter(filters).build())
         .orderBy(new Sorting("id"))
         .build();
      CustomPageDto<UserRemoteSessionDurationDto> userRemoteSessionDurationDtoPage = this.readRepository
         .find(
            query,
            tuple -> {
               UserRemoteSessionDurationDto userRemoteSessionDurationDto = new UserRemoteSessionDurationDto();
               userRemoteSessionDurationDto.setConnectionType(
                  this.connectionTypeConverter.convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue()))
               );
               userRemoteSessionDurationDto.setIpAddress((String)tuple.get("connectionIpAddress", String.class));
               long startTime = ((Number)tuple.get("startTime", Number.class)).longValue();
               long endTime = ((Number)tuple.get("endTime", Number.class)).longValue();
               userRemoteSessionDurationDto.setStartTime(startTime * 1000L);
               userRemoteSessionDurationDto.setDuration(endTime - startTime);
               return userRemoteSessionDurationDto;
            }
         );
      List<UserRemoteSessionDurationDto> userRemoteSessionDurationDtoList = userRemoteSessionDurationDtoPage.getContent();
      Collections.reverse(userRemoteSessionDurationDtoList);
      return userRemoteSessionDurationDtoList;
   }

   private long getTomorrowStartDayTimeAsEpochSeconds() {
      ZonedDateTime now = ZonedDateTime.now(ZoneId.of("UTC"));
      int year = now.get(ChronoField.YEAR);
      int month = now.get(ChronoField.MONTH_OF_YEAR);
      int day = now.get(ChronoField.DAY_OF_MONTH);
      return ZonedDateTime.of(year, month, day, 23, 59, 59, 0, ZoneId.of("UTC")).plusSeconds(1L).toInstant().getEpochSecond();
   }

   private int getUnitTimeInSeconds(TimeUnit timeUnit) {
      int base = 3600;
      if (timeUnit.equals(TimeUnit.YEAR)) {
         base *= 365;
      } else if (timeUnit.equals(TimeUnit.WEEK)) {
         base *= 7;
      }

      if (!timeUnit.equals(TimeUnit.HOUR)) {
         base *= 24;
      }

      return base;
   }

   private int getTotalTimeInSeconds(TimeUnit timeUnit, int count) {
      return timeUnit.equals(TimeUnit.MONTH) ? this.getTotalTimeInSecondsForMonthUnit(count) : this.getUnitTimeInSeconds(timeUnit) * count;
   }

   private int getTotalTimeInSecondsForMonthUnit(int count) {
      int currentMonth = this.getCurrentMonth();
      int totalDays = 0;

      for (int i = count; i >= 0; i--) {
         if (currentMonth < 1) {
            currentMonth = 12;
         }

         totalDays += Month.of(currentMonth).maxLength();
      }

      return totalDays * 24 * 3600;
   }

   private int getCurrentMonth() {
      return ZonedDateTime.now(ZoneId.of("UTC")).get(ChronoField.MONTH_OF_YEAR);
   }
}
