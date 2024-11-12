package ir.fidar.pam.session.websocket;

import ir.fidar.core.security.exception.UnauthorizedException;
import ir.fidar.core.security.sessionmanagement.AuthenticationAwareSessionInfo;
import ir.fidar.core.security.sessionmanagement.SessionService;
import ir.fidar.core.util.WebUtils;
import ir.fidar.pam.management.PamServletFiltersOrderHolder;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class BridgeWebsocketSecurityFilter implements Filter, Ordered {
   private final SessionService sessionService;

   public BridgeWebsocketSecurityFilter(SessionService sessionService) {
      this.sessionService = sessionService;
   }

   public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
      HttpServletRequest request = (HttpServletRequest)servletRequest;
      if (request.getRequestURI().startsWith("/api/remote-session")) {
         String token = servletRequest.getParameter("x-auth-token");
         if (token == null) {
            WebUtils.writeExceptionToResponse(new UnauthorizedException(), servletResponse);
            return;
         }

         AuthenticationAwareSessionInfo sessionInfo = (AuthenticationAwareSessionInfo)this.sessionService.getSessionInfo(token);
         if (sessionInfo == null) {
            WebUtils.writeExceptionToResponse(new UnauthorizedException(), servletResponse);
            return;
         }

         SecurityContextHolder.getContext().setAuthentication(sessionInfo.getAuthentication());
         filterChain.doFilter(servletRequest, servletResponse);
      } else {
         filterChain.doFilter(servletRequest, servletResponse);
      }
   }

   public int getOrder() {
      return PamServletFiltersOrderHolder.getOrder((Class<? extends Filter>)this.getClass());
   }
}
