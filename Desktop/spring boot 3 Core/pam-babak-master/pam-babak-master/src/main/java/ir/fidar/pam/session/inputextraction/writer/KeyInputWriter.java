package ir.fidar.pam.session.inputextraction.writer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SequenceWriter;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class KeyInputWriter implements ExtractedInputWriter<KeyInfo> {
   private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
   private final SequenceWriter writer;

   public KeyInputWriter(String storageFilePath) throws IOException {
      File file = new File(storageFilePath);
      if (!file.getParentFile().exists()) {
         Files.createDirectory(file.getParentFile().toPath());
      }

      this.writer = OBJECT_MAPPER.writer().writeValuesAsArray(file);
   }

   public void write(KeyInfo keyInfo) throws IOException {
      this.writer.write(keyInfo);
      this.writer.flush();
   }

   @Override
   public void close() throws IOException {
      this.writer.flush();
      this.writer.close();
   }
}
