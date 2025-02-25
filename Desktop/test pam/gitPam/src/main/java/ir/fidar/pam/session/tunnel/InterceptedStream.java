package ir.fidar.pam.session.tunnel;

import java.io.Closeable;
import java.io.OutputStream;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.protocol.GuacamoleStatus;

public class InterceptedStream<T extends Closeable> {
   private final String index;
   private final T stream;
   private final OutputStream fileOutputStream;
   private final InterceptedStreamCloseCallback closeCallback;
   private GuacamoleException streamError = null;

   public InterceptedStream(String index, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) {
      this(index, null, fileOutputStream, closeCallback);
   }

   public InterceptedStream(String index, T stream, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) {
      this.index = index;
      this.stream = stream;
      this.fileOutputStream = fileOutputStream;
      this.closeCallback = closeCallback;
   }

   public String getIndex() {
      return this.index;
   }

   public T getStream() {
      return this.stream;
   }

   public OutputStream getFileOutputStream() {
      return this.fileOutputStream;
   }

   public InterceptedStreamCloseCallback getCloseCallback() {
      return this.closeCallback;
   }

   public void setStreamError(GuacamoleException streamError) {
      this.streamError = streamError;
   }

   public void setStreamError(int code, String message) {
      GuacamoleStatus status = GuacamoleStatus.fromGuacamoleStatusCode(code);
      if (status == null) {
         status = GuacamoleStatus.SERVER_ERROR;
      }

      this.setStreamError(new GuacamoleStreamException(status, message));
   }

   public boolean hasStreamError() {
      return this.streamError != null;
   }

   public GuacamoleException getStreamError() {
      return this.streamError;
   }
}
