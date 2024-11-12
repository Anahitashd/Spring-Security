package ir.fidar.pam.service.impl;

import ir.fidar.core.da.repository.RoleRepository;
import ir.fidar.core.da.repository.UserGroupRepository;
import ir.fidar.core.da.repository.UserRepository;
import ir.fidar.core.domain.model.management.security.Role;
import ir.fidar.core.domain.type.UserAuthenticationMode;
import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.core.util.HttpMimeType;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.TemporalUtils;
import ir.fidar.core.util.WebUtils;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.domain.model.accessrule.AccessRule;
import ir.fidar.pam.domain.model.accessrule.AccessRuleConnection;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import ir.fidar.pam.domain.model.management.User;
import ir.fidar.pam.domain.model.management.UserGroup;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.type.ExcelExportSection;
import ir.fidar.pam.domain.type.ExcelImportSection;
import ir.fidar.pam.domain.type.FileTransferMode;
import ir.fidar.pam.exception.InvalidImportExcelFileFormatException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.IEService;
import ir.fidar.pam.service.connection.ConnectionService;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TimeZone;
import java.util.stream.Collectors;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Tuple;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.poi.poifs.macros.VBAMacroReader;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.HorizontalAlignment;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.VerticalAlignment;
import org.apache.poi.ss.util.CellUtil;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.multipart.MultipartFile;

@Service
public class IEServiceImpl implements IEService {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final String TEMPLATE_FILES_DIR = "/excel-import-templates";
   private static Map<String, String[]> FIELD_ORDER = new HashMap<>();
   private static final String USER_QUERY = "select u.username, u.email, u.firstName, u.lastName, u.authenticationMode, u.disabled, u.locked, u.locale, u.timezone, r.title from User u join u.role r";
   private static final String CONNECTION_QUERY = "select c.name, c.type, c.ipAddress, c.port, c.clipboard from Connection c";
   private static final String SESSION_FILTER_QUERY = "select s.name, s.regex from SessionInputConstraint s";
   private final EntityManagerFactory entityManagerFactory;
   private final RoleRepository roleRepository;
   private final UserRepository userRepository;
   private final UserGroupRepository userGroupRepository;
   private final SessionInputConstraintRepository sessionInputConstraintRepository;
   private final PasswordEncoder passwordEncoder;
   private final ConnectionService connectionService;

   public IEServiceImpl(
      EntityManagerFactory entityManagerFactory,
      RoleRepository roleRepository,
      UserRepository userRepository,
      UserGroupRepository userGroupRepository,
      SessionInputConstraintRepository sessionInputConstraintRepository,
      PasswordEncoder passwordEncoder,
      ConnectionService connectionService
   ) {
      this.entityManagerFactory = entityManagerFactory;
      this.roleRepository = roleRepository;
      this.userRepository = userRepository;
      this.userGroupRepository = userGroupRepository;
      this.sessionInputConstraintRepository = sessionInputConstraintRepository;
      this.passwordEncoder = passwordEncoder;
      this.connectionService = connectionService;
   }

   @Override
   public void importFromExcel(MultipartFile multipartFile, ExcelImportSection section) throws InvalidImportExcelFileFormatException {
      File file = this.convertMultipartToFile(multipartFile);

      XSSFWorkbook workbook;
      try {
         workbook = new XSSFWorkbook(file);
      } catch (Exception var69) {
         throw new InvalidImportExcelFileFormatException();
      }

      this.checkForMacros(file);
      XSSFSheet sheet = workbook.getSheetAt(0);
      Iterator<Row> rowIterator = sheet.rowIterator();
      rowIterator.next();
      switch (section) {
         case USER:
            List<User> users = new ArrayList<>();

            while (rowIterator.hasNext()) {
               User user = new User();
               XSSFRow row = (XSSFRow)rowIterator.next();
               Iterator<Cell> cellIteratorx = row.cellIterator();

               try {
                  user.setUsername(cellIteratorx.next().getStringCellValue());
               } catch (Exception var73) {
                  continue;
               }

               if (!Optional.ofNullable(this.userRepository.findOneByUsernameIgnoreCase(user.getUsername())).isPresent()) {
                  String temp = cellIteratorx.next().getStringCellValue();
                  Role role = Optional.ofNullable(this.roleRepository.findOneByTitleIgnoreCase(temp)).orElse(null);
                  if (role != null) {
                     user.setRole(role);

                     try {
                        user.setFirstName(cellIteratorx.next().getStringCellValue());
                        user.setLastName(cellIteratorx.next().getStringCellValue());
                     } catch (Exception var68) {
                     }

                     UserAuthenticationMode userAuthenticationMode = UserAuthenticationMode.EXTERNALLY;

                     try {
                        temp = cellIteratorx.next().getStringCellValue();
                        if (StringUtils.hasContent(temp)) {
                           userAuthenticationMode = UserAuthenticationMode.valueOf(temp);
                        }
                     } catch (Exception var66) {
                     } finally {
                        user.setAuthenticationMode(userAuthenticationMode);
                     }

                     temp = "fa";

                     try {
                        temp = cellIteratorx.next().getStringCellValue();
                     } catch (Exception var64) {
                     } finally {
                        user.setLocale(temp);
                     }

                     temp = "Asia/Tehran";

                     try {
                        temp = cellIteratorx.next().getStringCellValue();
                     } catch (Exception var62) {
                     } finally {
                        user.setTimezone(temp);
                     }

                     if (userAuthenticationMode.equals(UserAuthenticationMode.INTERNALLY)) {
                        user.setPassword(this.passwordEncoder.encode("Newuser@1"));
                     }

                     users.add(user);
                  }
               }
            }

            users.forEach(userx -> {
               if (userx.getAuthenticationMode().equals(UserAuthenticationMode.INTERNALLY)) {
                  userx.setCredentialExpirationTime(Instant.now().getEpochSecond() + 5L);
               }
            });
            this.userRepository.saveAll(users);
            break;
         case USER_GROUP:
            List<UserGroup> userGroups = new ArrayList<>();

            while (true) {
               UserGroup userGroup;
               Iterator<Cell> cellIterator;
               while (true) {
                  if (!rowIterator.hasNext()) {
                     this.userGroupRepository.saveAll(userGroups);
                     return;
                  }

                  userGroup = new UserGroup();
                  XSSFRow row = (XSSFRow)rowIterator.next();
                  cellIterator = row.cellIterator();

                  try {
                     userGroup.setName(cellIterator.next().getStringCellValue());
                     break;
                  } catch (Exception var71) {
                  }
               }

               if (!Optional.ofNullable(this.userGroupRepository.findOneByNameIgnoreCase(userGroup.getName())).isPresent()) {
                  try {
                     String[] users1 = StringUtils.split(cellIterator.next().getStringCellValue(), ",");

                     for (String username : users1) {
                        User user = (User)Optional.ofNullable(this.userRepository.findOneByUsernameIgnoreCase(username.trim())).orElse(null);
                        if (user != null) {
                           userGroup.addUser(user);
                        }
                     }

                     userGroups.add(userGroup);
                  } catch (Exception var72) {
                  }
               }
            }
         case SESSION_INPUT_CONSTRAINT:
            List<SessionInputConstraint> sessionInputConstraints = new ArrayList<>();

            while (rowIterator.hasNext()) {
               SessionInputConstraint sessionInputConstraint = new SessionInputConstraint();
               XSSFRow row = (XSSFRow)rowIterator.next();
               Iterator<Cell> cellIterator = row.cellIterator();

               try {
                  sessionInputConstraint.setName(cellIterator.next().getStringCellValue());
                  sessionInputConstraint.setRegex(cellIterator.next().getStringCellValue());
               } catch (Exception var70) {
                  continue;
               }

               if (!this.sessionInputConstraintRepository.exists(sessionInputConstraint.getName(), sessionInputConstraint.getRegex())) {
                  sessionInputConstraints.add(sessionInputConstraint);
               }
            }

            this.sessionInputConstraintRepository.saveAll(sessionInputConstraints);
            break;
         case CONNECTION:
            while (rowIterator.hasNext()) {
               Connection connection = new Connection();
               XSSFRow row = (XSSFRow)rowIterator.next();
               Iterator<Cell> cellIteratorx = row.cellIterator();
               FileTransferMode fileTransferMode = FileTransferMode.NONE;

               try {
                  connection.setName(cellIteratorx.next().getStringCellValue());
                  connection.setType(ConnectionType.valueOf(cellIteratorx.next().getStringCellValue()));
                  connection.setIpAddress(cellIteratorx.next().getStringCellValue());
                  connection.setPort(Double.valueOf(cellIteratorx.next().getNumericCellValue()).intValue());
                  connection.setClipboard(cellIteratorx.next().getBooleanCellValue());
                  fileTransferMode = FileTransferMode.valueOf(cellIteratorx.next().getStringCellValue());
               } catch (Exception var61) {
                  LOGGER.debug(Markers.EXCEL_IE, "Importing connection named '{}' failed to incorrect excel format", connection.getName(), var61);
               }

               try {
                  this.connectionService
                     .createNewRecord(
                        connection.getName(),
                        connection.getType(),
                        connection.getIpAddress(),
                        connection.getPort(),
                        connection.isClipboard(),
                        fileTransferMode,
                        null,
                        Collections.emptyList(),
                        Collections.emptyList(),
                        null
                     );
               } catch (Exception var60) {
                  LOGGER.debug(Markers.EXCEL_IE, "Importing connection named '{}' failed due to constraint validations", connection.getName(), var60);
               }
            }
      }
   }

   @Override
   public void downloadImportTemplate(ExcelImportSection section) throws IOException {
      HttpServletResponse response = (HttpServletResponse) ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getResponse();
      String templateFile = String.format("%s/%s", "/excel-import-templates", section.getTemplateFileName());
      WebUtils.writeStreamToResponse(
         response, new ClassPathResource(templateFile).getInputStream(), section.getTemplateFileName(), HttpMimeType.MS_XLSX.getValue()
      );
   }

   @Override
   public void exportToExcel(ExcelExportSection section) throws IOException {
      HttpServletResponse response = (HttpServletResponse) ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getResponse();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();
      List<IEServiceImpl.Record> records = new ArrayList<>();
      List<Tuple> tuples;
      List<Class<?>> tupleTypes;
      String[] fieldNames;
      try {
         switch (section) {
            case USER:
               tuples = entityManager.createQuery(
                     "select u.username, u.email, u.firstName, u.lastName, u.authenticationMode, u.disabled, u.locked, u.locale, u.timezone, r.title from User u join u.role r",
                     Tuple.class
                  )
                  .setHint("org.hibernate.readOnly", true)
                  .getResultList();
               tupleTypes = tuples.get(0).getElements().stream().map(tupleElement -> tupleElement.getJavaType()).collect(Collectors.toList());
               fieldNames = FIELD_ORDER.get(section.toString());

               for (Tuple tuple : tuples) {
                  List<IEServiceImpl.FieldValue> fieldValues = new ArrayList<>();

                  for (int j = 0; j < tupleTypes.size(); j++) {
                     String fieldName = fieldNames[j];
                     fieldValues.add(this.convertTupleToFieldValue(tuple, tupleTypes.get(j), j, fieldName));
                  }

                  records.add(new IEServiceImpl.Record(fieldValues));
               }
               break;
            case CONNECTION:
               tuples = entityManager.createQuery("select c.name, c.type, c.ipAddress, c.port, c.clipboard from Connection c", Tuple.class)
                  .setHint("org.hibernate.readOnly", true)
                  .getResultList();
               if (tuples.isEmpty()) {
                  response.setStatus(HttpStatus.NO_CONTENT.value());
                  return;
               }

               tupleTypes = tuples.get(0).getElements().stream().map(tupleElement -> tupleElement.getJavaType()).collect(Collectors.toList());
               fieldNames = FIELD_ORDER.get(section.toString());

               for (Tuple tuple : tuples) {
                  List<IEServiceImpl.FieldValue> fieldValues = new ArrayList<>();

                  for (int j = 0; j < tupleTypes.size(); j++) {
                     String fieldName = fieldNames[j];
                     fieldValues.add(this.convertTupleToFieldValue(tuple, tupleTypes.get(j), j, fieldName));
                  }

                  records.add(new IEServiceImpl.Record(fieldValues));
               }
               break;
            case SESSION_INPUT_CONSTRAINT:
               tuples = entityManager.createQuery("select s.name, s.regex from SessionInputConstraint s", Tuple.class)
                  .setHint("org.hibernate.readOnly", true)
                  .getResultList();
               if (tuples.isEmpty()) {
                  response.setStatus(HttpStatus.NO_CONTENT.value());
                  return;
               }

               tupleTypes = tuples.get(0).getElements().stream().map(tupleElement -> tupleElement.getJavaType()).collect(Collectors.toList());
               fieldNames = FIELD_ORDER.get(section.toString());

               for (Tuple tuple : tuples) {
                  List<IEServiceImpl.FieldValue> fieldValues = new ArrayList<>();

                  for (int j = 0; j < tupleTypes.size(); j++) {
                     String fieldName = fieldNames[j];
                     String value = tuple.get(j).toString();
                     Class type = String.class;
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldName, value, type));
                  }

                  records.add(new IEServiceImpl.Record(fieldValues));
               }
               break;
            case ACCESS_RULE:
               Set<AccessRule> accessRules = new HashSet<>(
                  entityManager.createQuery("SELECT ar FROM AccessRule ar JOIN FETCH ar.connections cons JOIN FETCH cons.connection c", AccessRule.class)
                     .setHint("org.hibernate.readOnly", true)
                     .getResultList()
               );
               if (accessRules.isEmpty()) {
                  response.setStatus(HttpStatus.NO_CONTENT.value());
                  return;
               }

               fieldNames = FIELD_ORDER.get(section.toString());

               for (AccessRule accessRule : accessRules) {
                  String bridge = (String)entityManager.createQuery("select b.name from AccessRule ar join ar.bridge b where ar.id=:id")
                     .setHint("org.hibernate.readOnly", true)
                     .setParameter("id", accessRule.getId())
                     .getSingleResult();

                  for (AccessRuleConnection accessRuleConnection : accessRule.getConnections()) {
                     List<IEServiceImpl.FieldValue> fieldValues = new ArrayList<>();
                     int i = 0;
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.getName(), String.class));
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRuleConnection.getConnection().getName(), String.class));
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRuleConnection.getConnection().getIpAddress(), String.class));
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRuleConnection.getConnection().getPort(), Integer.class));
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRuleConnection.getConnection().getType(), String.class));
                     fieldValues.add(
                        new IEServiceImpl.FieldValue(
                           fieldNames[i++], accessRuleConnection.getCredential() == null ? null : accessRuleConnection.getCredential().getLabel(), String.class
                        )
                     );
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], bridge, String.class));
                     fieldValues.add(
                        new IEServiceImpl.FieldValue(
                           fieldNames[i++],
                           accessRule.getExpirationTime() == 0L
                              ? ""
                              : TemporalUtils.format(
                                 LocalDateTime.ofEpochSecond(accessRule.getExpirationTime(), 0, ZoneOffset.UTC),
                                 TemporalUtils.TemporalPattern.TIMESTAMP_PATTERN
                              ),
                           String.class
                        )
                     );
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.isClipboard(), Boolean.class));
                     fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.getFileTransferMode(), String.class));
                     records.add(new IEServiceImpl.Record(fieldValues));
                  }

                  for (ConnectionGroup connectionGroup : accessRule.getConnectionGroups()) {
                     for (Connection connection : connectionGroup.getConnections()) {
                        List<IEServiceImpl.FieldValue> fieldValues = new ArrayList<>();
                        int i = 0;
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.getName(), String.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], connection.getName(), String.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], connection.getIpAddress(), String.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], connection.getPort(), Integer.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], connection.getType(), String.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], null, String.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], bridge, String.class));
                        fieldValues.add(
                           new IEServiceImpl.FieldValue(
                              fieldNames[i++],
                              accessRule.getExpirationTime() == 0L
                                 ? ""
                                 : TemporalUtils.format(
                                    LocalDateTime.ofEpochSecond(accessRule.getExpirationTime(), 0, ZoneOffset.UTC),
                                    TemporalUtils.TemporalPattern.TIMESTAMP_PATTERN
                                 ),
                              String.class
                           )
                        );
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.isClipboard(), Boolean.class));
                        fieldValues.add(new IEServiceImpl.FieldValue(fieldNames[i++], accessRule.getFileTransferMode(), String.class));
                        records.add(new IEServiceImpl.Record(fieldValues));
                     }
                  }
               }
               break;
            default:
               throw new IllegalStateException("Section's not supported");
         }

         File file = this.exportToExcel(section, records);
         WebUtils.writeFileToResponse(response, file, HttpMimeType.MS_XLSX.getValue());
      } finally {
         entityManager.close();
      }
   }

   private File convertMultipartToFile(MultipartFile multipartFile) {
      File file = new File(multipartFile.getName() + ".xlsx");
      FileOutputStream writer = null;

      try {
         writer = new FileOutputStream(file);
         writer.write(multipartFile.getBytes());
         writer.flush();
      } catch (IOException var13) {
         var13.printStackTrace();
      } finally {
         try {
            writer.close();
         } catch (IOException var12) {
            var12.printStackTrace();
         }
      }

      return file;
   }

   private IEServiceImpl.FieldValue convertTupleToFieldValue(Tuple tuple, Class tupleType, int index, String fieldName) {
      try {
         Object value;
         Class type;
         if (tupleType.equals(Long.class) || tupleType.equals(Integer.class)) {
            value = Long.parseLong(tuple.get(index).toString());
            type = Long.class;
         } else if (tupleType.equals(Double.class) || tupleType.equals(Float.class)) {
            value = Double.parseDouble(tuple.get(index).toString());
            type = Double.class;
         } else if (tupleType.equals(Boolean.class)) {
            value = Boolean.parseBoolean(tuple.get(index).toString());
            type = Boolean.class;
         } else if (tupleType.equals(ZonedDateTime.class)) {
            value = ((ZonedDateTime)tuple.get(index)).toString();
            type = String.class;
         } else if (tupleType.equals(TimeZone.class)) {
            value = ((TimeZone)tuple.get(index)).getID();
            type = String.class;
         } else if (tupleType.equals(Locale.class)) {
            value = ((Locale)tuple.get(index)).toLanguageTag();
            type = String.class;
         } else {
            value = tuple.get(index).toString();
            type = String.class;
         }

         return new IEServiceImpl.FieldValue(fieldName, value, type);
      } catch (Exception var8) {
         return new IEServiceImpl.FieldValue(fieldName, "", String.class);
      }
   }

   private File exportToExcel(ExcelExportSection section, List<IEServiceImpl.Record> records) {
      XSSFWorkbook workbook = new XSSFWorkbook();
      XSSFSheet sheet = workbook.createSheet(section.getExportFinalName());
      int rowNumber = 0;
      XSSFRow row = sheet.createRow(rowNumber++);
      int numberOfColumns = records.get(0).getFieldValues().size();
      int columnIndex = 0;
      int[] maxWidth = new int[numberOfColumns];
      int baseWidth = 12;
      List<String> titles = records.get(0).getFieldValues().stream().map(fieldValuex -> fieldValuex.getFieldName()).collect(Collectors.toList());

      for (int i = 0; i < numberOfColumns; i++) {
         XSSFCell cell = this.createCell(row, columnIndex);
         String fieldName = titles.get(i);
         int valueLength = fieldName.length();
         maxWidth[columnIndex] = this.maxWidth(baseWidth, maxWidth[columnIndex], valueLength);
         cell.setCellValue(fieldName);
         columnIndex++;
      }

      for (IEServiceImpl.Record record : records) {
         row = sheet.createRow(rowNumber++);
         columnIndex = 0;

         for (IEServiceImpl.FieldValue fieldValue : record.getFieldValues()) {
            XSSFCell cell = this.createCell(row, columnIndex);
            String value = String.valueOf(fieldValue.getValue());
            int valueLength = value.length();
            maxWidth[columnIndex] = this.maxWidth(baseWidth, maxWidth[columnIndex], valueLength);
            if (fieldValue.getType().equals(Double.class)) {
               cell.setCellValue(Double.valueOf(value));
            } else if (fieldValue.getType().equals(Long.class)) {
               cell.setCellValue((double)Long.valueOf(value).longValue());
            } else if (fieldValue.getType().equals(Boolean.class)) {
               cell.setCellValue(Boolean.valueOf(value));
            } else {
               cell.setCellValue(value);
            }

            columnIndex++;
         }
      }

      for (int i = 0; i < maxWidth.length; i++) {
         sheet.setColumnWidth(i, maxWidth[i] * 256);
      }

      File file = null;

      try {
         file = new File(String.format("%s.xlsx", section.getExportFinalName()));
         FileOutputStream writer = new FileOutputStream(file);
         workbook.write(writer);
         writer.flush();
         writer.close();
         workbook.close();
         return file;
      } catch (IOException var19) {
         throw new SystemInternalErrorException(var19);
      }
   }

   private XSSFCell createCell(XSSFRow row, int index) {
      XSSFCell cell = row.createCell(index);
      CellUtil.setAlignment(cell, HorizontalAlignment.CENTER);
      CellUtil.setVerticalAlignment(cell, VerticalAlignment.CENTER);
      return cell;
   }

   private int maxWidth(int baseWidth, int maxWidth, int valueLength) {
      if (valueLength < baseWidth) {
         if (baseWidth > maxWidth) {
            maxWidth = baseWidth;
         }
      } else if (valueLength > maxWidth) {
         maxWidth = valueLength;
      }

      return maxWidth;
   }

   private void checkForMacros(File file) throws InvalidImportExcelFileFormatException {
      boolean macroDetected;
      try {
         VBAMacroReader vbaMacroReader = new VBAMacroReader(file);
         Map macros = vbaMacroReader.readMacros();
         macroDetected = macros != null && !macros.isEmpty();
      } catch (IOException | IllegalArgumentException var5) {
         macroDetected = false;
      } catch (Exception var6) {
         LOGGER.debug(Markers.EXCEL_IE, "Unexpected error occurred while checking imported excel file for macros", var6);
         throw new SystemInternalErrorException(var6);
      }

      if (macroDetected) {
         throw new InvalidImportExcelFileFormatException();
      }
   }

   static {
      FIELD_ORDER.put(
         ExcelImportSection.USER.toString(),
         new String[]{"Username", "Email", "First Name", "Last Name", "Authentication Mode", "Disabled", "Locked", "Locale", "Timezone", "Role"}
      );
      FIELD_ORDER.put(ExcelImportSection.CONNECTION.toString(), new String[]{"Name", "Type", "Ip Address", "Port", "Clipboard"});
      FIELD_ORDER.put(ExcelImportSection.SESSION_INPUT_CONSTRAINT.toString(), new String[]{"Name", "Regex"});
      FIELD_ORDER.put(ExcelImportSection.USER_GROUP.toString(), new String[]{"Name", "Users"});
      FIELD_ORDER.put(
         ExcelExportSection.ACCESS_RULE.toString(),
         new String[]{
            "Name",
            "Connection Name",
            "Connection Ip Address",
            "Connection Port",
            "Connection Type",
            "Credential",
            "Bridge Name",
            "Expiration Date",
            "Clipboard",
            "File Transfer Mode"
         }
      );
   }

   private static class FieldValue {
      private String fieldName;
      private Object value;
      private Class type;

      public FieldValue(String fieldName, Object value, Class type) {
         this.fieldName = fieldName;
         this.value = value;
         this.type = type;
      }

      public String getFieldName() {
         return this.fieldName;
      }

      public Object getValue() {
         return this.value;
      }

      public Class getType() {
         return this.type;
      }

      @Override
      public String toString() {
         return "FieldValue{fieldName='" + this.fieldName + '\'' + ", value=" + this.value + ", type=" + this.type + '}';
      }
   }

   private static class Record {
      private List<IEServiceImpl.FieldValue> fieldValues;

      public Record(List<IEServiceImpl.FieldValue> fieldValues) {
         this.fieldValues = fieldValues;
      }

      public List<IEServiceImpl.FieldValue> getFieldValues() {
         return this.fieldValues;
      }

      @Override
      public String toString() {
         return "Record{fieldValues=" + this.fieldValues + '}';
      }
   }
}
