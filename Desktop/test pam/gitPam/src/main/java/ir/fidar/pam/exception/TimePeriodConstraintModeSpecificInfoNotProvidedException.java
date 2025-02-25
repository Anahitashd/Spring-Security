package ir.fidar.pam.exception;

import ir.fidar.core.exception.api.AbstractException;

public class TimePeriodConstraintModeSpecificInfoNotProvidedException extends AbstractException {
   @Override
   public String getCode() {
      return "time_period_const.crt.mode_info_not_provided";
   }
}
