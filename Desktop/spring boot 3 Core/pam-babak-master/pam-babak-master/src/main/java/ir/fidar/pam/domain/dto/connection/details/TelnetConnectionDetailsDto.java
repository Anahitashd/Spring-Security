package ir.fidar.pam.domain.dto.connection.details;

import ir.fidar.pam.domain.type.ColorScheme;

public class TelnetConnectionDetailsDto extends ConnectionDetailsDto {
   private ColorScheme colorScheme;
   private String fontName;
   private Integer fontSize;
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
