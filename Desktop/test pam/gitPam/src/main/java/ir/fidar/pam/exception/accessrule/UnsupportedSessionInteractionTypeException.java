package ir.fidar.pam.exception.accessrule;

import ir.fidar.core.exception.api.AbstractException;
import ir.fidar.pam.domain.type.SessionInteractionType;
import java.io.Serializable;
import java.util.Map;

public class UnsupportedSessionInteractionTypeException extends AbstractException {
   private SessionInteractionType sessionInteractionType;

   public UnsupportedSessionInteractionTypeException(SessionInteractionType sessionInteractionType) {
      this.sessionInteractionType = sessionInteractionType;
   }

   @Override
   public String getCode() {
      return "access_rule.session_interaction.unsupported";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("type", this.sessionInteractionType.toString().toLowerCase());
   }
}
