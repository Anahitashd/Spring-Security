package ir.fidar.pam.session.inputextraction.service;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class AdjustableThreadPoolExecutorService extends ThreadPoolExecutor {
   private static final int KEEP_ALIVE_TIMEOUT = 5;

   public AdjustableThreadPoolExecutorService(int maxPoolSize, ThreadFactory threadFactory) {
      this(maxPoolSize, threadFactory, new LinkedBlockingQueue<>());
   }

   public AdjustableThreadPoolExecutorService(int poolSize, ThreadFactory threadFactory, BlockingQueue<Runnable> queue) {
      super(poolSize, poolSize, 5L, TimeUnit.MINUTES, queue, threadFactory);
   }
}
