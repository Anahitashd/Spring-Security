package ir.fidar.pam.domain.dto;

import ir.fidar.core.domain.dto.crud.DetailsDto;
import ir.fidar.core.domain.dto.crud.ListDto;

public class SessionInputConstraintViolationIncidentDetailsDto implements ListDto, DetailsDto {
   private String input;
   private String regex;
   private long time;

   public String getInput() {
      return this.input;
   }

   public void setInput(String input) {
      this.input = input;
   }

   public String getRegex() {
      return this.regex;
   }

   public void setRegex(String regex) {
      this.regex = regex;
   }

   public long getTime() {
      return this.time;
   }

   public void setTime(long time) {
      this.time = time;
   }
}
