package ir.fidar.pam.session.tunnel;

import java.io.InputStream;
import java.io.OutputStream;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.net.DelegatingGuacamoleTunnel;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.FilteredGuacamoleReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StreamInterceptorTunnel extends DelegatingGuacamoleTunnel {
   private static final Logger logger = LoggerFactory.getLogger(StreamInterceptorTunnel.class);
   private final InputStreamInterceptorFilter inputStreamFilter = new InputStreamInterceptorFilter(this);
   private final OutputStreamInterceptorFilter outputStreamFilter = new OutputStreamInterceptorFilter(this);

   public StreamInterceptorTunnel(GuacamoleTunnel tunnel) {
      super(tunnel);
   }

   public void interceptStream(int index, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) throws GuacamoleException {
      this.interceptStream(index, (OutputStream)null, fileOutputStream, closeCallback);
   }

   public void interceptStream(int index, OutputStream stream, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) throws GuacamoleException {
      logger.debug("Intercepting output stream #{} of tunnel \"{}\".", index, this.getUUID());

      try {
         this.outputStreamFilter.interceptStream(index, stream, fileOutputStream, closeCallback);
      } finally {
         logger.debug("Intercepted output stream #{} of tunnel \"{}\" ended.", index, this.getUUID());
      }
   }

   public void interceptStream(int index, InputStream stream, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) throws GuacamoleException {
      logger.debug("Intercepting input stream #{} of tunnel \"{}\".", index, this.getUUID());

      try {
         this.inputStreamFilter.interceptStream(index, stream, fileOutputStream, closeCallback);
      } finally {
         logger.debug("Intercepted input stream #{} of tunnel \"{}\" ended.", index, this.getUUID());
      }
   }

   public GuacamoleReader acquireReader() {
      GuacamoleReader reader = super.acquireReader();
      GuacamoleReader var2 = new FilteredGuacamoleReader(reader, this.inputStreamFilter);
      return new FilteredGuacamoleReader(var2, this.outputStreamFilter);
   }

   public synchronized void close() throws GuacamoleException {
      try {
         super.close();
      } finally {
         this.inputStreamFilter.closeAllInterceptedStreams();
         this.outputStreamFilter.closeAllInterceptedStreams();
      }
   }
}
