package ir.fidar.pam.service.impl;

import ir.fidar.core.management.async.AsyncTaskExecutor;
import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.domain.dto.batchcommand.BatchCommandDto;
import ir.fidar.pam.domain.dto.batchcommand.BatchCommandResultDto;
import ir.fidar.pam.domain.model.credential.Credential;
import ir.fidar.pam.domain.model.credential.DomainCredential;
import ir.fidar.pam.domain.model.credential.PrivateKeyCredential;
import ir.fidar.pam.domain.model.credential.UsernamePasswordCredential;
import ir.fidar.pam.domain.type.CredentialType;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.BatchCommandService;
import ir.fidar.pam.session.ocr.OcrHostProperties;
import ir.fidar.pam.session.ocr.OcrRequest;
import ir.fidar.pam.session.ocr.OcrRequestExecutor;
import ir.fidar.pam.session.ocr.OcrRequestType;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.Tuple;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.io.GuacamoleReader;
import org.apache.guacamole.io.GuacamoleWriter;
import org.apache.guacamole.io.ReaderGuacamoleReader;
import org.apache.guacamole.net.GuacamoleSocket;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.InetGuacamoleSocket;
import org.apache.guacamole.net.SimpleGuacamoleTunnel;
import org.apache.guacamole.protocol.ConfiguredGuacamoleSocket;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.web.socket.TextMessage;

@Service
public class BatchCommandServiceImpl implements BatchCommandService {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final int DEFAULT_TIMEOUT_COUNTER_LIMIT = 15;
   private static final int NUMBER_OF_SYNC_BEFORE_SENDING_COMMAND = 4;
   private static final int DELAY_BEFORE_SENDING_COMMAND = 150;
   private static final int DELAY_BEFORE_PROCESSING_IMAGES = 250;
   private static final int DEFAULT_IMAGE_WIDTH = 1024;
   private static final int DEFAULT_IMAGE_HEIGHT = 768;
   private final EntityManagerFactory entityManagerFactory;
   private final OcrHostProperties ocrHostProperties;
   private final AsyncTaskExecutor asyncTaskExecutor;
   private static Map<String, Integer> COMMON_COMMANDS_PROCESSING_TIME = new HashMap<>();

   public BatchCommandServiceImpl(EntityManagerFactory entityManagerFactory, OcrHostProperties ocrHostProperties, AsyncTaskExecutor asyncTaskExecutor) {
      this.entityManagerFactory = entityManagerFactory;
      this.ocrHostProperties = ocrHostProperties;
      this.asyncTaskExecutor = asyncTaskExecutor;
   }

   @Override
   public List<BatchCommandResultDto> executeCommands(List<BatchCommandDto> batchCommandDtoList) throws InterruptedException {
      List<BatchCommandResultDto> resultDtoList = new ArrayList<>();
      Thread[] threads = new Thread[batchCommandDtoList.size()];
      int index = 0;

      for (BatchCommandDto batchCommandDto : batchCommandDtoList) {
         Thread thread = new Thread(new BatchCommandServiceImpl.BatchCommandExecutor(resultDtoList, batchCommandDto, 1024, 768));
         LOGGER.debug(
            Markers.SESSION,
            "About to execute batch command {} on connection {} using bridge {}",
            batchCommandDto.getCommand(),
            batchCommandDto.getConnectionName(),
            batchCommandDto.getBridgeName()
         );
         thread.start();
         threads[index++] = thread;
      }

      for (Thread thread : threads) {
         thread.join();
      }

      return resultDtoList;
   }

   static {
      COMMON_COMMANDS_PROCESSING_TIME.put("ls", 2);
      COMMON_COMMANDS_PROCESSING_TIME.put("ll", 2);
      COMMON_COMMANDS_PROCESSING_TIME.put("rm", 3);
      COMMON_COMMANDS_PROCESSING_TIME.put("cp", 3);
      COMMON_COMMANDS_PROCESSING_TIME.put("mv", 5);
      COMMON_COMMANDS_PROCESSING_TIME.put("sudo", 2);
      COMMON_COMMANDS_PROCESSING_TIME.put("top", 5);
      COMMON_COMMANDS_PROCESSING_TIME.put("cat", 7);
      COMMON_COMMANDS_PROCESSING_TIME.put("less", 3);
      COMMON_COMMANDS_PROCESSING_TIME.put("tail", 7);
   }

   private class BatchCommandExecutor implements Runnable {
      private final List<BatchCommandResultDto> resultDtoList;
      private final BatchCommandDto batchCommandDto;
      private final int imageWidth;
      private final int imageHeight;
      private final String uuid;
      private EntityManager entityManager;

      public BatchCommandExecutor(List<BatchCommandResultDto> resultDtoList, BatchCommandDto batchCommandDto, int imageWidth, int imageHeight) {
         this.resultDtoList = resultDtoList;
         this.batchCommandDto = batchCommandDto;
         this.imageWidth = imageWidth;
         this.imageHeight = imageHeight;
         this.uuid = UUID.randomUUID().toString();
         this.entityManager = BatchCommandServiceImpl.this.entityManagerFactory.createEntityManager();
      }

      @Override
      public void run() {
         String command = this.batchCommandDto.getCommand();
         String connectionName = this.batchCommandDto.getConnectionName();
         String bridgeName = this.batchCommandDto.getBridgeName();
         String credentialLabel = this.batchCommandDto.getCredentialLabel();
         Tuple tuple = (Tuple)this.entityManager
            .createQuery("select b.ipAddress, b.port from Bridge b where UPPER(b.name) = UPPER(:name)", Tuple.class)
            .setHint("org.hibernate.readOnly", true)
            .setParameter("name", this.batchCommandDto.getBridgeName())
            .getSingleResult();
         String bridgeIpAddress = (String)tuple.get(0, String.class);
         int bridgePort = ((Number)tuple.get(1, Number.class)).intValue();
         tuple = (Tuple)this.entityManager
            .createQuery("select c.ipAddress, c.port, c.id from Connection c where UPPER(c.name)=UPPER(:name)", Tuple.class)
            .setHint("org.hibernate.readOnly", true)
            .setParameter("name", this.batchCommandDto.getConnectionName())
            .getSingleResult();
         String hostIpAddress = (String)tuple.get(0, String.class);
         int hostPort = ((Number)tuple.get(1, Number.class)).intValue();
         Credential credential = null;
         if (StringUtils.hasContent(credentialLabel)) {
            long connectionId = ((Number)tuple.get(2, Number.class)).longValue();
            tuple = (Tuple)this.entityManager
               .createQuery("select c.id, c.type from Credential c where UPPER(c.label)=UPPER(:label) and c.connection.id=:cid", Tuple.class)
               .setHint("org.hibernate.readOnly", true)
               .setParameter("label", credentialLabel)
               .setParameter("cid", connectionId)
               .getSingleResult();
            long id = ((Number)tuple.get(0, Number.class)).longValue();
            CredentialType credentialType = (CredentialType)tuple.get(1, CredentialType.class);
            switch (credentialType) {
               case USERNAME_PASSWORD:
                  credential = (Credential)this.entityManager
                     .createQuery("select c from UsernamePasswordCredential c where c.id=:id", UsernamePasswordCredential.class)
                     .setParameter("id", id)
                     .getSingleResult();
                  break;
               case PRIVATE_KEY:
                  credential = (Credential)this.entityManager
                     .createQuery("select c from DomainCredential c where c.id=:id", DomainCredential.class)
                     .setParameter("id", id)
                     .getSingleResult();
                  break;
               case DOMAIN:
                  credential = (Credential)this.entityManager
                     .createQuery("select c from PrivateKeyCredential c where c.id=:id", PrivateKeyCredential.class)
                     .setParameter("id", id)
                     .getSingleResult();
            }
         }

         this.entityManager.close();
         GuacamoleConfiguration guacamoleConfiguration = new GuacamoleConfiguration();
         guacamoleConfiguration.setProtocol("ssh");
         Map<String, String> parameters = new HashMap<>();
         parameters.put("hostname", hostIpAddress);
         parameters.put("port", String.valueOf(hostPort));
         if (credential != null) {
            switch (credential.getType()) {
               case USERNAME_PASSWORD:
                  UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential)credential;
                  parameters.put("username", usernamePasswordCredential.getUsername());
                  parameters.put("password", usernamePasswordCredential.getPassword());
                  break;
               case PRIVATE_KEY:
                  PrivateKeyCredential privateKeyCredential = (PrivateKeyCredential)credential;
                  parameters.put("username", privateKeyCredential.getUsername());
                  parameters.put("private-key", privateKeyCredential.getPrivateKey());
                  parameters.put("passphrase", privateKeyCredential.getPassphrase());
                  break;
               case DOMAIN:
                  DomainCredential domainCredential = (DomainCredential)credential;
                  parameters.put("username", domainCredential.getUsername());
                  parameters.put("password", domainCredential.getPassword());
                  parameters.put("domain", domainCredential.getDomain());
            }
         } else {
            parameters.put("username", this.batchCommandDto.getUsername());
            parameters.put("password", this.batchCommandDto.getPassword());
         }

         guacamoleConfiguration.setParameters(parameters);

         try {
            GuacamoleSocket socket = new ConfiguredGuacamoleSocket(
               new InetGuacamoleSocket(bridgeIpAddress, bridgePort), guacamoleConfiguration, new GuacamoleClientInformation()
            );
            GuacamoleTunnel tunnel = new SimpleGuacamoleTunnel(socket);
            OcrRequestExecutor ocrRequestExecutor = new OcrRequestExecutor(BatchCommandServiceImpl.this.ocrHostProperties);
            Thread reader = new Thread(BatchCommandServiceImpl.this.new ReaderThread(ocrRequestExecutor, tunnel, this.uuid, this.batchCommandDto.getCommand()));
            reader.start();
            ocrRequestExecutor.startListening();
            Map<String, String> query = new HashMap<>();
            query.put("width", String.valueOf(this.imageWidth));
            query.put("height", String.valueOf(this.imageHeight));
            query.put("type", "batch-command");
            ocrRequestExecutor.registerRequest(new OcrRequest(this.uuid, OcrRequestType.INIT, query));
            synchronized (tunnel) {
               tunnel.wait();
            }

            Thread.sleep(250L);
            File file = new File(String.format("%s/%s", BatchCommandServiceImpl.this.ocrHostProperties.getBatchCommandPath(), this.uuid));
            if (file.exists()) {
               File[] imageFiles = file.listFiles();
               List<String> images = new ArrayList<>();

               for (File imageFile : imageFiles) {
                  BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(imageFile));
                  byte[] bytes = new byte[Long.valueOf(imageFile.length()).intValue()];
                  bufferedInputStream.read(bytes);
                  bufferedInputStream.close();
                  String imageData = new String(Base64.getEncoder().encode(bytes), "UTF-8");
                  images.add(imageData);
               }

               BatchCommandResultDto resultDto = new BatchCommandResultDto();
               resultDto.setLabel(this.batchCommandDto.getLabel());
               resultDto.setResults(images);
               synchronized (this.resultDtoList) {
                  this.resultDtoList.add(resultDto);
                  return;
               }
            }

            BatchCommandServiceImpl.LOGGER
               .info(Markers.SESSION, "Batch command {} is executed successfully on connection {} using bridge {}", command, connectionName, bridgeName);
         } catch (InterruptedException | IOException | GuacamoleException var31) {
            BatchCommandServiceImpl.LOGGER
               .error(
                  Markers.SESSION,
                  "An unexpected error occurred on executing batch command {} is executed successfully on connection {} using bridge {}",
                  command,
                  connectionName,
                  bridgeName
               );
         }
      }
   }

   private class ReaderThread implements Runnable {
      private static final int DELAY_BEFORE_SENDING_SYNC = 25;
      private final OcrRequestExecutor ocrRequestExecutor;
      private final GuacamoleTunnel tunnel;
      private final String uuid;
      private final String command;
      private int timeoutCounterLimit;
      private int timeoutCounter;
      private int initializationCounter;
      private boolean initialized;

      public ReaderThread(OcrRequestExecutor ocrRequestExecutor, GuacamoleTunnel tunnel, String uuid, String command) {
         this.ocrRequestExecutor = ocrRequestExecutor;
         this.tunnel = tunnel;
         this.uuid = uuid;
         this.command = command;
         this.timeoutCounter = 0;
         this.initialized = false;
         this.initializationCounter = 0;
         this.initializeTimeoutCounterLimit(command);
      }

      @Override
      public void run() {
         StringBuilder buffer = new StringBuilder(8192);
         GuacamoleReader reader = this.tunnel.acquireReader();

         try {
            char[] readMessage;
            while ((readMessage = reader.read()) != null) {
               buffer.append(readMessage);
               if (!reader.available() || buffer.length() >= 8192) {
                  String content = buffer.toString();
                  TextMessage message = new TextMessage(content);
                  this.ocrRequestExecutor.registerRequest(new OcrRequest(this.uuid, OcrRequestType.CAPTURE, (String)message.getPayload(), null));
                  if (content.equals("10.disconnect;") || content.endsWith("10.disconnect;")) {
                     this.close();
                     return;
                  }

                  if (content.startsWith("4.sync,")) {
                     Thread.sleep(25L);
                     GuacamoleReader guacamoleReader = new ReaderGuacamoleReader(new StringReader(content));
                     GuacamoleInstruction guacamoleInstruction = guacamoleReader.readInstruction();
                     GuacamoleWriter writer = this.tunnel.acquireWriter();

                     try {
                        writer.writeInstruction(guacamoleInstruction);
                        this.tunnel.releaseWriter();
                     } catch (GuacamoleException var10) {
                        var10.printStackTrace();
                     }

                     if (!this.initialized) {
                        this.initializationCounter++;
                     }

                     if (this.initializationCounter == 4) {
                        if (!this.initialized) {
                           this.initialized = true;
                           BatchCommandServiceImpl.this.asyncTaskExecutor
                              .executeTask(BatchCommandServiceImpl.this.new SendCommandTask(this.tunnel, this.command), 150, TimeUnit.MILLISECONDS);
                        } else {
                           this.timeoutCounter++;
                           if (this.timeoutCounter == this.timeoutCounterLimit) {
                              this.close();
                              return;
                           }
                        }
                     }
                  } else if (this.initialized) {
                     this.timeoutCounter = 0;
                  } else {
                     this.initializationCounter = 0;
                  }

                  buffer.setLength(0);
               }
            }

            this.close();
         } catch (InterruptedException | GuacamoleException var11) {
            Exception e = var11;

            try {
               this.close();
               e.printStackTrace();
            } catch (GuacamoleException var9) {
               var9.printStackTrace();
            }
         }
      }

      private void close() throws GuacamoleException {
         GuacamoleWriter writer = this.tunnel.acquireWriter();
         writer.writeInstruction(new GuacamoleInstruction("disconnect", new String[0]));
         this.tunnel.releaseWriter();
         this.tunnel.close();
         this.ocrRequestExecutor.registerRequest(new OcrRequest(this.uuid, OcrRequestType.CLOSE, null));
         this.ocrRequestExecutor.shutDown();
         synchronized (this.tunnel) {
            this.tunnel.notify();
         }
      }

      private void initializeTimeoutCounterLimit(String command) {
         Integer temp = BatchCommandServiceImpl.COMMON_COMMANDS_PROCESSING_TIME.get(command);
         if (temp != null) {
            this.timeoutCounterLimit = temp;
         } else {
            temp = BatchCommandServiceImpl.COMMON_COMMANDS_PROCESSING_TIME.get(String.format("%s;", command));
            if (temp != null) {
               this.timeoutCounterLimit = temp;
            } else {
               String[] parts = command.split(";");
               if (parts.length == 1) {
                  this.timeoutCounterLimit = 15;
               } else {
                  int sum = 0;

                  for (String part : parts) {
                     part = part.trim();
                     temp = BatchCommandServiceImpl.COMMON_COMMANDS_PROCESSING_TIME.get(part);
                     if (temp != null) {
                        sum += temp;
                     } else {
                        temp = BatchCommandServiceImpl.COMMON_COMMANDS_PROCESSING_TIME.get(String.format("%s;", command));
                        if (temp != null) {
                           sum += temp;
                        } else {
                           sum += 15;
                        }
                     }
                  }

                  this.timeoutCounterLimit = sum + 2;
               }
            }
         }
      }
   }

   private class SendCommandTask implements Runnable {
      private final GuacamoleTunnel tunnel;
      private final String command;

      public SendCommandTask(GuacamoleTunnel tunnel, String command) {
         this.tunnel = tunnel;
         this.command = command;
      }

      @Override
      public void run() {
         for (GuacamoleInstruction instruction : this.convertCommandToGuacamoleInstruction(this.command)) {
            try {
               GuacamoleWriter writer = this.tunnel.acquireWriter();
               writer.writeInstruction(instruction);
               this.tunnel.releaseWriter();
            } catch (GuacamoleException var5) {
               var5.printStackTrace();
            }
         }
      }

      private List<GuacamoleInstruction> convertCommandToGuacamoleInstruction(String command) {
         List<GuacamoleInstruction> instructions = new ArrayList<>();
         char[] characters = command.toCharArray();

         for (int i = 0; i < characters.length; i++) {
            GuacamoleInstruction instruction = new GuacamoleInstruction("key", new String[]{String.valueOf(characters[i]), "1"});
            instructions.add(instruction);
            instruction = new GuacamoleInstruction("key", new String[]{String.valueOf(characters[i]), "0"});
            instructions.add(instruction);
         }

         GuacamoleInstruction instruction = new GuacamoleInstruction("key", new String[]{"65293", "1"});
         instructions.add(instruction);
         instruction = new GuacamoleInstruction("key", new String[]{"65293", "0"});
         instructions.add(instruction);
         return instructions;
      }
   }
}
