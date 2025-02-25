package ir.fidar.pam.exception.credential;

import ir.fidar.core.exception.api.AbstractException;
import java.io.Serializable;
import java.util.Map;

public class CredentialLabelAlreadyExists extends AbstractException {
   private String label;

   public CredentialLabelAlreadyExists(String label) {
      this.label = label;
   }

   @Override
   public String getCode() {
      return "cred.lbl.dup";
   }

   @Override
   public Map<String, Serializable> getInfo() {
      return this.buildInfo().add("label", this.label);
   }
}
