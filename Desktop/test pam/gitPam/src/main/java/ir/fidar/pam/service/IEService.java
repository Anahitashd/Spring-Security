package ir.fidar.pam.service;

import ir.fidar.core.exception.management.UserGroupNameAlreadyInUseException;
import ir.fidar.core.exception.management.user.UsernameAlreadyInUseException;
import ir.fidar.pam.domain.type.ExcelExportSection;
import ir.fidar.pam.domain.type.ExcelImportSection;
import ir.fidar.pam.exception.InvalidImportExcelFileFormatException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintNameAlreadyExistsException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintRegexAlreadyExistsException;
import java.io.IOException;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.springframework.web.multipart.MultipartFile;

public interface IEService {
   void importFromExcel(MultipartFile var1, ExcelImportSection var2) throws IOException, InvalidFormatException, UsernameAlreadyInUseException, UserGroupNameAlreadyInUseException, SessionInputConstraintNameAlreadyExistsException, SessionInputConstraintRegexAlreadyExistsException, InvalidImportExcelFileFormatException;

   void downloadImportTemplate(ExcelImportSection var1) throws IOException;

   void exportToExcel(ExcelExportSection var1) throws IOException;
}
