package ir.fidar.pam.management;

import ir.fidar.core.management.ServletFiltersOrderHolder;
import ir.fidar.pam.session.websocket.BridgeWebsocketSecurityFilter;

public class PamServletFiltersOrderHolder extends ServletFiltersOrderHolder {
   @Override
   protected void registerFilterOrders() {
      FILTER_ORDER_MAPPER.put(BridgeWebsocketSecurityFilter.class, 2147480147);
   }
}
