package ir.fidar.pam.session.inputextraction.model.consoletype;

public interface ResolvableInput<T> {
   T getContent();

   boolean isComparable();

   boolean matchesContent(String var1);

   void resolve() throws Exception;
}
