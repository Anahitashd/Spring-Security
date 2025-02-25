package ir.fidar.pam.session.inputextraction.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties({"type", "pressed"})
public class KeyInfo {
   private final int keysym;
   private final int unicode;
   private final String name;
   private final String character;
   private final boolean pressed;
   private final long time;
   private final KeyType type;

   public KeyInfo(
      @JsonProperty("keysym") int keysym,
      @JsonProperty("unicode") int unicode,
      @JsonProperty("name") String name,
      @JsonProperty("character") String character,
      boolean pressed,
      @JsonProperty("time") long time,
      KeyType type
   ) {
      this.keysym = keysym;
      this.unicode = unicode;
      this.name = name;
      this.character = character;
      this.pressed = pressed;
      this.time = time;
      this.type = type;
   }

   public int getKeysym() {
      return this.keysym;
   }

   public int getUnicode() {
      return this.unicode;
   }

   public String getName() {
      return this.name;
   }

   public String getCharacter() {
      return this.character;
   }

   public boolean isPressed() {
      return this.pressed;
   }

   public long getTime() {
      return this.time;
   }

   public KeyType getType() {
      return this.type;
   }
}
