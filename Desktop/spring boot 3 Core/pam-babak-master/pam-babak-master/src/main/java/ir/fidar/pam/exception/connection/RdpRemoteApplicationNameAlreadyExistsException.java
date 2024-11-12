package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class RdpRemoteApplicationNameAlreadyExistsException extends AbstractException {
   private final String name;

   public RdpRemoteApplicationNameAlreadyExistsException(String name) {
      this.name = name;
   }

   @Override
   public String getCode() {
      return "con.remote_app.name.dup";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("name", this.name);
   }
}
