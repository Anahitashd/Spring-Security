package ir.fidar.pam.session.inputextraction.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;

public enum InputSource {
   SERVER(1),
   CLIENT(2);

   private final int code;

   private InputSource(int code) {
      this.code = code;
   }

   @JsonValue
   public int getCode() {
      return this.code;
   }

   @JsonCreator
   public InputSource getValue(int code) {
      return Stream.of(values()).filter(value -> value.getCode() == code).findFirst().orElse(null);
   }
}
