package ir.fidar.pam.session.inputextraction.model;

public class ClipboardInfo {
   private final String content;
   private final InputSource source;
   private final int time;

   public ClipboardInfo(String content, InputSource source, int time) {
      this.content = content;
      this.source = source;
      this.time = time;
   }

   public String getContent() {
      return this.content;
   }

   public InputSource getSource() {
      return this.source;
   }

   public int getTime() {
      return this.time;
   }
}
