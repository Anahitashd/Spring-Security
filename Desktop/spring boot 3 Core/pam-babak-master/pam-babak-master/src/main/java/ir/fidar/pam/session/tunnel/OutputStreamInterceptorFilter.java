package ir.fidar.pam.session.tunnel;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import javax.xml.bind.DatatypeConverter;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.guacamole.protocol.GuacamoleStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OutputStreamInterceptorFilter extends StreamInterceptorFilter<OutputStream> {
   private static final Logger logger = LoggerFactory.getLogger(OutputStreamInterceptorFilter.class);
   private boolean acknowledgeBlobs = true;

   public OutputStreamInterceptorFilter(GuacamoleTunnel tunnel) {
      super(tunnel);
   }

   private void sendAck(String index, String message, GuacamoleStatus status) {
      if (status != GuacamoleStatus.SUCCESS) {
         this.closeInterceptedStream(index);
      }

      this.sendInstruction(new GuacamoleInstruction("ack", new String[]{index, message, Integer.toString(status.getGuacamoleStatusCode())}));
   }

   private GuacamoleInstruction handleBlob(GuacamoleInstruction instruction) {
      List<String> args = instruction.getArgs();
      if (args.size() < 2) {
         return instruction;
      } else {
         String index = args.get(0);
         InterceptedStream<OutputStream> stream = this.getInterceptedStream(index);
         if (stream == null) {
            return instruction;
         } else {
            byte[] blob;
            try {
               String data = args.get(1);
               blob = DatatypeConverter.parseBase64Binary(data);
            } catch (IllegalArgumentException var8) {
               logger.warn("Received base64 data for intercepted stream was invalid.");
               logger.debug("Decoding base64 data for intercepted stream failed.", var8);
               return null;
            }

            try {
               if (stream.getStream() != null) {
                  stream.getStream().write(blob);
               }

               if (stream.getFileOutputStream() != null) {
                  stream.getFileOutputStream().write(blob);
                  stream.getFileOutputStream().flush();
               }

               if (!this.acknowledgeBlobs) {
                  this.acknowledgeBlobs = true;
                  return new GuacamoleInstruction("blob", new String[]{index, ""});
               }

               this.sendAck(index, "OK", GuacamoleStatus.SUCCESS);
            } catch (IOException var71) {
               this.sendAck(index, "FAIL", GuacamoleStatus.SERVER_ERROR);
               logger.debug("Write failed for intercepted stream.", var71);
            }

            return null;
         }
      }
   }

   private void handleEnd(GuacamoleInstruction instruction) {
      List<String> args = instruction.getArgs();
      if (args.size() >= 1) {
         this.closeInterceptedStream(args.get(0));
      }
   }

   private void handleSync(GuacamoleInstruction instruction) {
      this.acknowledgeBlobs = false;
   }

   public GuacamoleInstruction filter(GuacamoleInstruction instruction) throws GuacamoleException {
      if (instruction.getOpcode().equals("blob")) {
         return this.handleBlob(instruction);
      } else if (instruction.getOpcode().equals("end")) {
         this.handleEnd(instruction);
         return instruction;
      } else if (instruction.getOpcode().equals("sync")) {
         this.handleSync(instruction);
         return instruction;
      } else {
         return instruction;
      }
   }

   @Override
   protected void handleInterceptedStream(InterceptedStream<OutputStream> stream) {
      this.sendAck(stream.getIndex(), "OK", GuacamoleStatus.SUCCESS);
   }
}
