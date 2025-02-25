package ir.fidar.pam.session.tunnel;

import java.io.Closeable;
import java.io.OutputStream;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.GuacamoleWriter;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.GuacamoleFilter;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class StreamInterceptorFilter<T extends Closeable> implements GuacamoleFilter {
   private static final Logger logger = LoggerFactory.getLogger(StreamInterceptorFilter.class);
   private final InterceptedStreamMap<T> streams = new InterceptedStreamMap<>();
   private final GuacamoleTunnel tunnel;

   public StreamInterceptorFilter(GuacamoleTunnel tunnel) {
      this.tunnel = tunnel;
   }

   protected void sendInstruction(GuacamoleInstruction instruction) {
      GuacamoleWriter writer = this.tunnel.acquireWriter();

      try {
         writer.writeInstruction(instruction);
      } catch (GuacamoleException var4) {
         logger.debug("Unable to send \"{}\" for intercepted stream.", instruction.getOpcode(), var4);
      }

      this.tunnel.releaseWriter();
   }

   protected InterceptedStream<T> getInterceptedStream(String index) {
      return this.streams.get(index);
   }

   protected InterceptedStream<T> closeInterceptedStream(String index) {
      return this.streams.close(index);
   }

   protected boolean closeInterceptedStream(InterceptedStream<T> stream) {
      return this.streams.close(stream);
   }

   public void closeAllInterceptedStreams() {
      this.streams.closeAll();
   }

   protected abstract void handleInterceptedStream(InterceptedStream<T> var1);

   public void interceptStream(int index, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) throws GuacamoleException {
      this.interceptStream(index, null, fileOutputStream, closeCallback);
   }

   public void interceptStream(int index, T stream, OutputStream fileOutputStream, InterceptedStreamCloseCallback closeCallback) throws GuacamoleException {
      String indexString = Integer.toString(index);
      InterceptedStream interceptedStream;
      synchronized (this.tunnel) {
         if (!this.tunnel.isOpen()) {
            return;
         }

         interceptedStream = new InterceptedStream(indexString, stream, fileOutputStream, closeCallback);
         this.streams.put(interceptedStream);
      }

      this.handleInterceptedStream(interceptedStream);
      this.streams.waitFor(interceptedStream);
      if (interceptedStream.hasStreamError()) {
         throw interceptedStream.getStreamError();
      }
   }
}
