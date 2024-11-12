package ir.fidar.pam.controller.management;

import ir.fidar.core.exception.management.UserGroupNameAlreadyInUseException;
import ir.fidar.core.exception.management.user.UsernameAlreadyInUseException;
import ir.fidar.pam.domain.type.ExcelExportSection;
import ir.fidar.pam.domain.type.ExcelImportSection;
import ir.fidar.pam.exception.InvalidImportExcelFileFormatException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintNameAlreadyExistsException;
import ir.fidar.pam.exception.sessioninputconstraint.SessionInputConstraintRegexAlreadyExistsException;
import ir.fidar.pam.service.IEService;
import java.io.IOException;
import jakarta.validation.constraints.NotNull;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping({"/api/management/excel-ie"})
public class IEController {
   private final IEService ieService;

   public IEController(IEService ieService) {
      this.ieService = ieService;
   }

   @GetMapping(
      value = {"/export"},
      params = {"section"}
   )
   public ResponseEntity export(@RequestParam("section") ExcelExportSection section) throws IOException {
      this.ieService.exportToExcel(section);
      return ResponseEntity.ok().build();
   }

   @PostMapping(
      value = {"/import"},
      params = {"section"}
   )
   public ResponseEntity importFromExcel(
      @NotNull(message = "null.section") @RequestParam("section") ExcelImportSection section,
      @NotNull(message = "null.file") @RequestParam("file") MultipartFile file
   ) throws IOException, InvalidFormatException, UsernameAlreadyInUseException, SessionInputConstraintNameAlreadyExistsException, SessionInputConstraintRegexAlreadyExistsException, UserGroupNameAlreadyInUseException, InvalidImportExcelFileFormatException {
      this.ieService.importFromExcel(file, section);
      return ResponseEntity.ok().build();
   }

   @GetMapping(
      value = {"/download-import-template"},
      params = {"section"}
   )
   public ResponseEntity downloadImportTemplate(@RequestParam("section") ExcelImportSection section) throws IOException, InvalidFormatException, UsernameAlreadyInUseException, SessionInputConstraintNameAlreadyExistsException, SessionInputConstraintRegexAlreadyExistsException, UserGroupNameAlreadyInUseException {
      this.ieService.downloadImportTemplate(section);
      return ResponseEntity.ok().build();
   }
}
