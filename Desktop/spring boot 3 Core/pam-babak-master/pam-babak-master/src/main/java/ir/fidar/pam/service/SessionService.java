package ir.fidar.pam.service;

import ir.fidar.core.exception.FileNotFoundException;
import ir.fidar.pam.exception.session.InsufficientPrivilegeToAccessSessionException;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

public interface SessionService {
   void terminateLiveSession(String var1) throws Exception;

   StreamingResponseBody downloadStream(String var1, int var2, String var3) throws Exception;

   void uploadStream(String var1, int var2, String var3) throws Exception;

   void closeTransparentSession(String var1);

   StreamingResponseBody downloadRequestedFile(String var1, String var2) throws FileNotFoundException, InsufficientPrivilegeToAccessSessionException;
}
