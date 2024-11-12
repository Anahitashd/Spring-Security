package ir.fidar.pam.session.inputextraction.model;

public class FunctionalKeysState implements Cloneable {
   private FunctionalKeysState.FunctionalKey shift = new FunctionalKeysState.FunctionalKey();
   private FunctionalKeysState.FunctionalKey ctrl = new FunctionalKeysState.FunctionalKey();

   public FunctionalKeysState.FunctionalKey getShift() {
      return this.shift;
   }

   public FunctionalKeysState.FunctionalKey getCtrl() {
      return this.ctrl;
   }

   @Override
   public Object clone() throws CloneNotSupportedException {
      FunctionalKeysState functionalKeysState = (FunctionalKeysState)super.clone();
      functionalKeysState.shift = (FunctionalKeysState.FunctionalKey)this.getShift().clone();
      functionalKeysState.ctrl = (FunctionalKeysState.FunctionalKey)this.getCtrl().clone();
      return functionalKeysState;
   }

   public static class FunctionalKey implements Cloneable {
      private boolean pressed;

      public void set() {
         this.pressed = true;
      }

      public void reset() {
         this.pressed = false;
      }

      public boolean isPressed() {
         return this.pressed;
      }

      @Override
      public Object clone() throws CloneNotSupportedException {
         return super.clone();
      }
   }
}
