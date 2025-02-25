package ir.fidar.pam.session.tunnel;

import java.io.Closeable;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InterceptedStreamMap<T extends Closeable> {
   private static final Logger logger = LoggerFactory.getLogger(InterceptedStreamMap.class);
   private static final long STREAM_WAIT_TIMEOUT = 1000L;
   private final ConcurrentMap<String, InterceptedStream<T>> streams = new ConcurrentHashMap<>();

   private void close(T stream) {
      if (stream != null) {
         try {
            stream.close();
         } catch (IOException var5) {
            logger.warn("Unable to close intercepted stream: {}", var5.getMessage());
            logger.debug("I/O error prevented closure of intercepted stream.", var5);
         }

         synchronized (stream) {
            stream.notify();
         }
      }
   }

   public InterceptedStream<T> close(String index) {
      InterceptedStream<T> stream = this.streams.remove(index);
      if (stream == null) {
         return null;
      } else {
         this.close(stream.getStream());

         try {
            if (stream.getFileOutputStream() != null) {
               stream.getFileOutputStream().close();
            }
         } catch (IOException var4) {
         }

         if (stream.getCloseCallback() != null) {
            stream.getCloseCallback().onClose();
         }

         return stream;
      }
   }

   public boolean close(InterceptedStream<T> stream) {
      boolean wasRemoved = this.streams.remove(stream.getIndex(), stream);
      this.close(stream.getStream());
      return wasRemoved;
   }

   public void closeAll() {
      for (InterceptedStream<T> stream : this.streams.values()) {
         this.close(stream.getStream());
      }

      this.streams.clear();
   }

   public void waitFor(InterceptedStream<T> stream) {
      T underlyingStream = stream.getStream();
      if (underlyingStream != null) {
         synchronized (underlyingStream) {
            while (this.streams.get(stream.getIndex()) == stream) {
               try {
                  underlyingStream.wait(1000L);
               } catch (InterruptedException var6) {
               }
            }
         }
      }
   }

   public InterceptedStream<T> get(String index) {
      return this.streams.get(index);
   }

   public void put(InterceptedStream<T> stream) {
      InterceptedStream<T> oldStream = this.streams.put(stream.getIndex(), stream);
      if (oldStream != null) {
         this.close(oldStream.getStream());
      }
   }
}
