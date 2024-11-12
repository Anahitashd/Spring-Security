package ir.fidar.pam.session.inputextraction.model.consoletype;

public abstract class AbstractResolvableInput<T> implements ResolvableInput<T> {
   protected final ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction;
   private final T content;

   protected AbstractResolvableInput(ConsoleTypeRemoteSessionInputExtraction remoteSessionInputExtraction, T content) {
      this.remoteSessionInputExtraction = remoteSessionInputExtraction;
      this.content = content;
   }

   @Override
   public T getContent() {
      return this.content;
   }
}
