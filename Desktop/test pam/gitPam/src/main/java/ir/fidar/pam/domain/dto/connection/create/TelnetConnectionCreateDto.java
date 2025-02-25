package ir.fidar.pam.domain.dto.connection.create;

import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.dto.connection.update.ConnectionUpdateDto;
import ir.fidar.pam.domain.type.ColorScheme;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

public class TelnetConnectionCreateDto extends ConnectionUpdateDto {
   @NotNull(
      message = "null.colorScheme"
   )
   private ColorScheme colorScheme;
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
   @Size(
      max = 255,
      message = "gt_max.passwordRegex"
   )
   private String passwordRegex;
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

   public String getPasswordRegex() {
      return this.passwordRegex;
   }

   public void setPasswordRegex(String passwordRegex) {
      this.passwordRegex = passwordRegex;
   }

   public boolean isBastion() {
      return this.bastion;
   }

   public void setBastion(boolean bastion) {
      this.bastion = bastion;
   }
}
