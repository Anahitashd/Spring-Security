package ir.fidar.pam.session.inputextraction.service;

import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import org.jetbrains.annotations.NotNull;

public class NamePrefixAwareThreadFactory implements ThreadFactory {
   private static final ThreadFactory DEFAULT_THREAD_FACTORY = Executors.defaultThreadFactory();
   private final AtomicInteger threadNumber = new AtomicInteger(1);
   private final String threadNamePrefix;

   public NamePrefixAwareThreadFactory(String threadNamePrefix) {
      this.threadNamePrefix = threadNamePrefix;
   }

   @Override
   public Thread newThread(@NotNull Runnable r) {
      Thread thread = DEFAULT_THREAD_FACTORY.newThread(r);
      thread.setName(String.format("%s-thread-%d", this.threadNamePrefix, this.threadNumber.getAndIncrement()));
      return thread;
   }
}
