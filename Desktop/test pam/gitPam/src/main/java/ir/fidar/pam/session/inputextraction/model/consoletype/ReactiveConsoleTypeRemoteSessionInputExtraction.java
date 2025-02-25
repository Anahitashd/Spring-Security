package ir.fidar.pam.session.inputextraction.model.consoletype;

import ir.fidar.core.util.StringUtils;
import ir.fidar.pam.domain.model.session.CaptureExecutedCommand;
import ir.fidar.pam.service.CaptureService;
import ir.fidar.pam.session.ManagedSession;
import ir.fidar.pam.session.inputextraction.SpecialKeys;
import ir.fidar.pam.session.inputextraction.model.ClipboardInfo;
import ir.fidar.pam.session.inputextraction.model.KeyInfo;
import ir.fidar.pam.session.inputextraction.model.ReactiveRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.model.callback.RemoteSessionExtractionStatusChangeCallback;
import ir.fidar.pam.session.inputextraction.writer.ExtractedInputWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ReactiveConsoleTypeRemoteSessionInputExtraction extends ReactiveRemoteSessionInputExtraction implements ConsoleTypeRemoteSessionInputExtraction {
   private final BlockingQueue<ResolvableInput> resolvableInputs;
   private final StringBuilder commandBuffer;
   private final ExtractedInputWriter<String> commandWriter;
   private String lastTransmittedClipboard;

   public ReactiveConsoleTypeRemoteSessionInputExtraction(
      ManagedSession managedSession,
      ExtractedInputWriter<KeyInfo> keyWriter,
      ExtractedInputWriter<ClipboardInfo> clipboardWriter,
      ReactiveConsoleTypeRemoteSessionInputExtraction.CommandInputWriter commandWriter,
      RemoteSessionExtractionStatusChangeCallback readyCallback
   ) throws IOException {
      super(managedSession, keyWriter, clipboardWriter, readyCallback);
      commandWriter.setRemoteSessionInputExtraction(this);
      this.commandWriter = commandWriter;
      this.resolvableInputs = new LinkedBlockingQueue<>();
      this.commandBuffer = new StringBuilder();
   }

   @Override
   public void addResolvableInput(ResolvableInput resolvableInput) {
      this.resolvableInputs.add(resolvableInput);
   }

   @Override
   public void processResolvableInputs(String imageContent) {
      if (StringUtils.hasContent(imageContent)) {
         imageContent = imageContent.trim();

         try {
            label90:
            while (!this.resolvableInputs.isEmpty()) {
               ResolvableInput resolvableInput = this.resolvableInputs.poll();
               if (resolvableInput instanceof KeyInput && SpecialKeys.SPACE.getX11Coeds().contains(((KeyInput)resolvableInput).getContent().getKeysym())) {
                  resolvableInput.resolve();
               } else if (!resolvableInput.isComparable()) {
                  resolvableInput.resolve();
               } else if (imageContent.length() == 1) {
                  if (resolvableInput.matchesContent(imageContent)) {
                     resolvableInput.resolve();
                     break;
                  }
               } else if (imageContent.equals("AC") && resolvableInput instanceof KeyInput) {
                  KeyInput keyInput = (KeyInput)resolvableInput;
                  if (SpecialKeys.C.getX11Coeds().contains(keyInput.getContent().getKeysym()) && keyInput.getFunctionalKeysState().getCtrl().isPressed()) {
                     keyInput.resolve();
                  }
               } else if (resolvableInput instanceof ClipboardInput) {
                  if (resolvableInput.matchesContent(imageContent)) {
                     resolvableInput.resolve();
                     break;
                  }
               } else if (this.resolvableInputs.size() >= imageContent.length()) {
                  ResolvableInput nextInput = resolvableInput;

                  for (int i = 0; i < imageContent.length() && nextInput != null; i++) {
                     String character = String.valueOf(imageContent.charAt(i));
                     if (nextInput.isComparable() && !nextInput.matchesContent(character)) {
                        continue label90;
                     }

                     nextInput = this.resolvableInputs.peek();
                     if (nextInput == null && i != imageContent.length() - 1) {
                        continue label90;
                     }
                  }

                  resolvableInput.resolve();

                  for (int i = 1; i < imageContent.length(); i++) {
                     this.resolvableInputs.poll().resolve();
                  }
                  break;
               }
            }
         } catch (Exception var6) {
            this.logError(var6, "resolving input");
         }
      }
   }

   @Override
   public void setLastTransmittedClipboard(String lastTransmittedClipboard) {
      this.lastTransmittedClipboard = lastTransmittedClipboard;
   }

   @Override
   public String getLastTransmittedClipboard() {
      return this.lastTransmittedClipboard;
   }

   @Override
   public void clearCommandBuffer() {
      this.commandBuffer.setLength(0);
   }

   @Override
   public void appendToCommand(String str) {
      if (str != null) {
         this.commandBuffer.append(str);
      }
   }

   @Override
   public void removeLastCharacterFromCommandBuffer() {
      if (this.commandBuffer.length() > 0) {
         this.commandBuffer.delete(this.commandBuffer.length() - 1, this.commandBuffer.length());
      }
   }

   @Override
   public void flushCommandBuffer() {
      if (this.commandBuffer.length() > 0) {
         try {
            this.commandWriter.write(this.commandBuffer.toString());
         } catch (Exception var5) {
            this.logError(var5, "flushing input extraction command buffer");
         } finally {
            this.commandBuffer.setLength(0);
         }
      }
   }

   @Override
   public boolean isTabPressed() {
      boolean result = false;
      if (!this.resolvableInputs.isEmpty()) {
         Iterator<ResolvableInput> resolvableInputIterator = this.resolvableInputs.iterator();
         boolean tabEncountered = false;
         boolean tabExists = false;

         while (true) {
            if (!resolvableInputIterator.hasNext()) {
               result = tabExists;
               break;
            }

            ResolvableInput resolvableInput = resolvableInputIterator.next();
            if (resolvableInput instanceof KeyInput) {
               KeyInput keyInput = (KeyInput)resolvableInput;
               if (SpecialKeys.TAB.getX11Coeds().contains(keyInput.getContent().getKeysym())) {
                  tabExists = true;
                  if (tabEncountered) {
                     break;
                  }

                  tabEncountered = true;
               } else {
                  tabEncountered = false;
               }
            }
         }
      }

      return result;
   }

   @Override
   protected void clearIoResources() {
      try {
         if (!this.resolvableInputs.isEmpty()) {
            for (ResolvableInput resolvableInput : this.resolvableInputs) {
               try {
                  if (!resolvableInput.isComparable()) {
                     resolvableInput.resolve();
                  }

                  if (resolvableInput instanceof KeyInput && SpecialKeys.ENTER.getX11Coeds().contains(((KeyInput)resolvableInput).getContent().getKeysym())) {
                     this.flushCommandBuffer();
                  }
               } catch (Exception var8) {
                  super.logError(var8, String.format("resolving unresolved input '%s'", resolvableInput.toString()));
               }
            }
         }

         this.commandWriter.close();
      } catch (IOException var9) {
         super.logError(var9, "closing command input writers");
      } finally {
         super.clearIoResources();
      }
   }

   public static class CommandInputWriter implements ExtractedInputWriter<String> {
      private final CaptureService captureService;
      private ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction;

      public CommandInputWriter(CaptureService captureService) {
         this.captureService = captureService;
      }

      public void setRemoteSessionInputExtraction(ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction) {
         this.remoteSessionInputExtraction = remoteSessionInputExtraction;
      }

      public void write(String data) throws IOException {
         long now = this.remoteSessionInputExtraction.getCurrentProcessingTask().getRegistrationTime();
         CaptureExecutedCommand captureExecutedCommand = new CaptureExecutedCommand();
         captureExecutedCommand.setContent(data);
         captureExecutedCommand.setTime(now);
         captureExecutedCommand.setElapsedTime((int)this.remoteSessionInputExtraction.getElapsedTime());
         this.captureService.addExecutedCommand(this.remoteSessionInputExtraction.getManagedSession().getId(), captureExecutedCommand);
      }

      @Override
      public void close() throws IOException {
      }
   }
}
