package ir.fidar.pam.session.inputextraction.writer;

import java.io.Closeable;
import java.io.IOException;

public interface ExtractedInputWriter<T> extends Closeable {
   void write(T var1) throws IOException;
}
