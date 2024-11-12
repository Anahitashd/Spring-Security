package ir.fidar.pam.session.ocr;

import ir.fidar.pam.da.repository.SessionCapturedImageRepository;
import ir.fidar.pam.domain.model.ocr.SessionCapturedImage;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public class OcrStorageFolderWatcher implements Runnable {
   private final WatchService watchService;
   private final Path path;
   private final String sessionId;
   private final String storagePath;
   private final SessionCapturedImageRepository sessionCapturedImageRepository;
   private boolean valid;
   private boolean sessionClosed;

   public OcrStorageFolderWatcher(String sessionId, SessionCapturedImageRepository sessionCapturedImageRepository, OcrHostProperties ocrHostProperties) throws IOException {
      this.sessionId = sessionId;
      this.sessionCapturedImageRepository = sessionCapturedImageRepository;
      this.storagePath = String.format("%s/%s", ocrHostProperties.getStoragePath(), sessionId);
      this.path = Paths.get(this.storagePath);
      this.valid = true;
      this.sessionClosed = false;
      this.watchService = FileSystems.getDefault().newWatchService();
      this.path.register(this.watchService, StandardWatchEventKinds.ENTRY_CREATE);
   }

   public void close() {
      this.sessionClosed = true;
   }

   @Override
   public void run() {
      while (true) {
         try {
            WatchKey key;
            if (this.sessionClosed) {
               key = this.watchService.poll(10000L, TimeUnit.MILLISECONDS);
               if (key == null) {
                  return;
               }
            } else {
               key = this.watchService.take();
            }

            for (WatchEvent event : key.pollEvents()) {
               Thread.sleep(150L);
               File imageFile = new File(String.format("%s/%s", this.storagePath, event.context()));
               BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(imageFile));
               byte[] bytes = new byte[Long.valueOf(imageFile.length()).intValue()];
               bufferedInputStream.read(bytes);
               bufferedInputStream.close();
               String imageData = new String(Base64.getEncoder().encode(bytes), "UTF-8");
               SessionCapturedImage sessionImage = new SessionCapturedImage();
               sessionImage.setSessionId(this.sessionId);
               sessionImage.setImageData(imageData);
               this.sessionCapturedImageRepository.save(sessionImage);
            }

            this.valid = key.reset();
            if (!this.valid) {
               return;
            }
         } catch (FileNotFoundException | InterruptedException var9) {
            var9.printStackTrace();
         } catch (UnsupportedEncodingException var10) {
            var10.printStackTrace();
         } catch (IOException var11) {
            var11.printStackTrace();
         }
      }
   }
}
