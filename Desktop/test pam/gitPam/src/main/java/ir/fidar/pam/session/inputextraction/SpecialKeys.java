package ir.fidar.pam.session.inputextraction;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum SpecialKeys {
   ENTER(Collections.singleton(65293)),
   SHIFT(Stream.of(65505, 65506).collect(Collectors.toSet())),
   CTRL(Stream.of(65507, 65508).collect(Collectors.toSet())),
   BACK_SPACE(Stream.of(65288).collect(Collectors.toSet())),
   C(Stream.of(67, 99).collect(Collectors.toSet())),
   TAB(Stream.of(65289).collect(Collectors.toSet())),
   L(Stream.of(76, 108).collect(Collectors.toSet())),
   SPACE(Stream.of(32, 65408).collect(Collectors.toSet()));

   private final Set<Integer> x11Coeds;

   private SpecialKeys(Set<Integer> x11Coeds) {
      this.x11Coeds = x11Coeds;
   }

   public Set<Integer> getX11Coeds() {
      return this.x11Coeds;
   }
}
