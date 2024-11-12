package ir.fidar.pam.domain.dto.credential.create;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonSubTypes.Type;
import com.fasterxml.jackson.annotation.JsonTypeInfo.As;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import ir.fidar.core.domain.dto.crud.CreateDto;
import ir.fidar.core.domain.util.constraint.ValidName;
import ir.fidar.core.security.validation.XssProtected;
import ir.fidar.pam.domain.type.CredentialType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@JsonTypeInfo(
   use = Id.NAME,
   include = As.PROPERTY,
   property = "type",
   visible = true
)
@JsonSubTypes({@Type(
      value = UsernamePasswordCredentialCreateDto.class,
      name = "USERNAME_PASSWORD"
   ), @Type(
      value = DomainCredentialCreateDto.class,
      name = "DOMAIN"
   ), @Type(
      value = PrivateKeyCredentialCreateDto.class,
      name = "PRIVATE_KEY"
   )})
public class CredentialCreateDto implements CreateDto {
   @NotNull(
      message = "null.type"
   )
   private CredentialType type;
   @ValidName
   @Size(
      max = 48,
      message = "gt_max.label"
   )
   @XssProtected
   private String label;

   public CredentialType getType() {
      return this.type;
   }

   public void setType(CredentialType type) {
      this.type = type;
   }

   public String getLabel() {
      return this.label;
   }

   public void setLabel(String label) {
      this.label = label;
   }
}
