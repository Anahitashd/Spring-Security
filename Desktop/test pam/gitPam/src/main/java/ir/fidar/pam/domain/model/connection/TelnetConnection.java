package ir.fidar.pam.domain.model.connection;

import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.ColorScheme;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ColorSchemeConverter;
import javax.persistence.CascadeType;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.MapsId;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.constraints.Max;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Entity
@Table(
   name = "tb_telnet_connection"
)
public class TelnetConnection {
   @Id
   private Long id;
   @NotNull(
      message = "null.colorScheme"
   )
   @Convert(
      converter = ColorSchemeConverter.class
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
   @Size(
      max = 255,
      message = "gt_max.passwordRegex"
   )
   private String passwordRegex;
   private boolean bastion;
   @OneToOne(
      fetch = FetchType.LAZY,
      cascade = {CascadeType.MERGE}
   )
   @JoinColumn(
      name = "id"
   )
   @MapsId
   private Connection connection;

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

   public Connection getConnection() {
      return this.connection;
   }

   public void setConnection(Connection connection) {
      this.connection = connection;
   }

   @Override
   public boolean equals(Object o) {
      return super.equals(o);
   }

   @Override
   public int hashCode() {
      return super.hashCode();
   }
}
