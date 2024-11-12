package ir.fidar.pam.domain.model.accessrule;

import java.io.Serializable;
import java.util.Objects;
import jakarta.persistence.Embeddable;
import jakarta.validation.constraints.NotNull;

@Embeddable
public class AccessRuleConnectionId implements Serializable {
   @NotNull(
      message = "null.access_rule_id"
   )
   private Long accessRuleId;
   @NotNull(
      message = "null.connection_id"
   )
   private Long connectionId;

   public AccessRuleConnectionId() {
   }

   public AccessRuleConnectionId(Long accessRuleId, Long connectionId) {
      this.accessRuleId = accessRuleId;
      this.connectionId = connectionId;
   }

   public Long getAccessRuleId() {
      return this.accessRuleId;
   }

   public Long getConnectionId() {
      return this.connectionId;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      } else if (o != null && this.getClass() == o.getClass()) {
         AccessRuleConnectionId that = (AccessRuleConnectionId)o;
         return this.accessRuleId.equals(that.accessRuleId) && this.connectionId.equals(that.connectionId);
      } else {
         return false;
      }
   }

   @Override
   public int hashCode() {
      return Objects.hash(this.accessRuleId, this.connectionId);
   }
}
