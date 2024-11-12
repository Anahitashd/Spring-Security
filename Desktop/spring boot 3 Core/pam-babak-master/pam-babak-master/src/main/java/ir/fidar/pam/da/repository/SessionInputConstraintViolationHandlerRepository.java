package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import java.util.Set;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionInputConstraintViolationHandlerRepository extends GenericRepository<SessionInputConstraintViolationHandler, Long> {
   Set<SessionInputConstraintViolationHandler> findAllByConnectionId(Long var1);

   @Query("select s from SessionInputConstraintViolationHandler s join s.inputConstraint ic on ic.regex=:constRegex where s.connection.id=:connectionId")
   SessionInputConstraintViolationHandler findOneByConstraintIdAndConnectionId(@Param("constRegex") String var1, @Param("connectionId") Long var2);

   @Query("select s from SessionInputConstraintViolationHandler s join s.inputConstraint ic on ic.regex=:constRegex where s.accessRule.id=:accessRuleId")
   SessionInputConstraintViolationHandler findOneByConstraintIdAndAccessRuleId(@Param("constRegex") String var1, @Param("accessRuleId") Long var2);

   @Modifying
   @Query("DELETE FROM SessionInputConstraintViolationHandler s WHERE s.connection.id = :connectionId")
   void deleteAllByConnectionId(@Param("connectionId") Long var1);

   @Modifying
   @Query("DELETE FROM SessionInputConstraintViolationHandler s WHERE s.connection.id = :connectionId AND s.inputConstraint.regex = :constraintRegex")
   void deleteOneByConnectionIdAndInputConstraintRegex(@Param("connectionId") Long var1, @Param("constraintRegex") String var2);

   void deleteAllByAccessRuleId(Long var1);
}
