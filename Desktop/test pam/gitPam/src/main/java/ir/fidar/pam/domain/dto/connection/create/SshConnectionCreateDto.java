package ir.fidar.pam.domain.dto.connection.create;

import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.ColorScheme;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class SshConnectionCreateDto extends FileTransferSupportConnectionCreateDto {
   @NotNull(
      message = "null.colorScheme"
   )
   private ColorScheme colorScheme;
   @Size(
      max = 64,
      message = "gt_max.fontName"
   )
   @XssProtected
   private String fontName;
   @NotNull(
      message = "null.fontSize"
   )
   @Min(
      value = 8L,
      message = "lt_min.fontSize"
   )
   @Max(
      value = 32L,
      message = "gt_max.fontSize"
   )
   private Integer fontSize;
   private boolean bastion;

   public ColorScheme getColorScheme() {
      return this.colorScheme;
   }

   public void setColorScheme(ColorScheme colorScheme) {
      this.colorScheme = colorScheme;
   }

   public String getFontName() {
      return this.fontName;
   }

   public void setFontName(String fontName) {
      this.fontName = fontName;
   }

   public Integer getFontSize() {
      return this.fontSize;
   }

   public void setFontSize(Integer fontSize) {
      this.fontSize = fontSize;
   }

   public boolean isBastion() {
      return this.bastion;
   }

   public void setBastion(boolean bastion) {
      this.bastion = bastion;
   }
}
