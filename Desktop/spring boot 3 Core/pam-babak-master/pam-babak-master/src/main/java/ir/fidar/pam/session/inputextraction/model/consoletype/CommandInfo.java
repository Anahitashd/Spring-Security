package ir.fidar.pam.session.inputextraction.model.consoletype;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CommandInfo {
   private final String command;
   private final long time;

   public CommandInfo(@JsonProperty("command") String command, @JsonProperty("time") long time) {
      this.command = command;
      this.time = time;
   }

   public String getCommand() {
      return this.command;
   }

   public long getTime() {
      return this.time;
   }
}
