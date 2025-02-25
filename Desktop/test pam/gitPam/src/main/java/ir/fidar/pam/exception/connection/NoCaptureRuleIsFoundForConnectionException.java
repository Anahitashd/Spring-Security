package ir.fidar.pam.exception.connection;

import ir.fidar.core.exception.api.AbstractException;

public class NoCaptureRuleIsFoundForConnectionException extends AbstractException {
   @Override
   public String getCode() {
      return "connection.capture_rule.not_set";
   }
}
