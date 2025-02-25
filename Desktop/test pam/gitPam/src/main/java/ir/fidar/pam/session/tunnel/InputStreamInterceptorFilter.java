package ir.fidar.pam.session.tunnel;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import javax.xml.bind.DatatypeConverter;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.guacamole.protocol.GuacamoleStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class InputStreamInterceptorFilter extends StreamInterceptorFilter<InputStream> {
   private static final Logger logger = LoggerFactory.getLogger(InputStreamInterceptorFilter.class);

   public InputStreamInterceptorFilter(GuacamoleTunnel tunnel) {
      super(tunnel);
   }

   private void sendBlob(String index, byte[] blob) {
      this.sendInstruction(new GuacamoleInstruction("blob", new String[]{index, DatatypeConverter.printBase64Binary(blob)}));
   }

   private void sendEnd(String index) {
      this.sendInstruction(new GuacamoleInstruction("end", new String[]{index}));
   }

   private void readNextBlob(InterceptedStream<InputStream> stream) {
      try {
         byte[] blob = new byte[6048];
         int length = stream.getStream().read(blob);
         if (length == -1) {
            if (this.closeInterceptedStream(stream)) {
               this.sendEnd(stream.getIndex());
            }

            return;
         }

         if (stream.getFileOutputStream() != null) {
            stream.getFileOutputStream().write(blob, 0, length);
            stream.getFileOutputStream().flush();
         }

         this.sendBlob(stream.getIndex(), Arrays.copyOf(blob, length));
      } catch (IOException var41) {
         logger.debug("Unable to read data of intercepted input stream.", var41);
         if (this.closeInterceptedStream(stream)) {
            this.sendEnd(stream.getIndex());
         }
      }
   }

   private void handleAck(GuacamoleInstruction instruction) {
      List<String> args = instruction.getArgs();
      if (args.size() >= 3) {
         String index = args.get(0);
         InterceptedStream<InputStream> stream = this.getInterceptedStream(index);
         if (stream != null) {
            String status = args.get(2);
            if (!status.equals("0")) {
               int code;
               try {
                  code = Integer.parseInt(status);
               } catch (NumberFormatException var8) {
                  logger.debug("Translating invalid status code \"{}\" to SERVER_ERROR.", status);
                  code = GuacamoleStatus.SERVER_ERROR.getGuacamoleStatusCode();
               }

               stream.setStreamError(code, args.get(1));
               this.closeInterceptedStream(stream);
            } else {
               this.readNextBlob(stream);
            }
         }
      }
   }

   public GuacamoleInstruction filter(GuacamoleInstruction instruction) throws GuacamoleException {
      if (instruction.getOpcode().equals("ack")) {
         this.handleAck(instruction);
      }

      return instruction;
   }

   @Override
   protected void handleInterceptedStream(InterceptedStream<InputStream> stream) {
      this.readNextBlob(stream);
   }
}
