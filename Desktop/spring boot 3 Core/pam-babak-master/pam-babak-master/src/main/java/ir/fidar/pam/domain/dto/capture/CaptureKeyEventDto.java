package ir.fidar.pam.domain.dto.capture;

import ir.fidar.core.domain.dto.crud.ListDto;

public class CaptureKeyEventDto implements ListDto {
   private int keysym;
   private int unicode;
   private String name;
   private String character;
   private int time;

   public int getKeysym() {
      return this.keysym;
   }

   public void setKeysym(int keysym) {
      this.keysym = keysym;
   }

   public int getUnicode() {
      return this.unicode;
   }

   public void setUnicode(int unicode) {
      this.unicode = unicode;
   }

   public String getName() {
      return this.name;
   }

   public void setName(String name) {
      this.name = name;
   }

   public String getCharacter() {
      return this.character;
   }

   public void setCharacter(String character) {
      this.character = character;
   }

   public int getTime() {
      return this.time;
   }

   public void setTime(int time) {
      this.time = time;
   }
}
