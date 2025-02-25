package ir.fidar.pam.domain.dto.connection;

import ir.fidar.core.security.validation.CustomizedXssProtected;
import ir.fidar.core.security.validation.XssProtected;
import java.util.Objects;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

public class RdpConnectionRemoteApplicationCreateDto {
   @NotBlank(
      message = "blank.name"
   )
   @Size(
      max = 64,
      message = "gt_max.name"
   )
   @XssProtected
   private String name;
   @Size(
      max = 255,
      message = "gt_max.workingDirectory"
   )
   @CustomizedXssProtected(
      skippingCharacters = {'/', '\\', ':'}
   )
   private String workingDirectory;
   @Size(
      max = 255,
      message = "gt_max.params"
   )
   private String params;

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getWorkingDirectory() {
      return this.workingDirectory;
   }

   public void setWorkingDirectory(String workingDirectory) {
      this.workingDirectory = workingDirectory;
   }

   public String getParams() {
      return this.params;
   }

   public void setParams(String params) {
      this.params = params;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         RdpConnectionRemoteApplicationCreateDto that = (RdpConnectionRemoteApplicationCreateDto)o;
         return this.name.equals(that.name);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.name);
   }
}
