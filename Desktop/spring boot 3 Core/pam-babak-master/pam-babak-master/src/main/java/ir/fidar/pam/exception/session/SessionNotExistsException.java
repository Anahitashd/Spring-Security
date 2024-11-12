package ir.fidar.pam.exception.session;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class SessionNotExistsException extends AbstractException {
   private final String uuid;

   public SessionNotExistsException(String uuid) {
      this.uuid = uuid;
   }

   @Override
   public String getCode() {
      return "session.not_found";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("uuid", this.uuid);
   }
}
