package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionInputConstraintRepository extends GenericRepository<SessionInputConstraint, Long> {
   SessionInputConstraint findOneByNameIgnoreCase(String var1);

   @Query("select s from SessionInputConstraint s where s.regex=:regex")
   SessionInputConstraint findOneByRegex(@Param("regex") String var1);

   @Query(
      value = "SELECT EXISTS(SELECT id FROM `tb_session_input_constraint` sic WHERE sic.name = :name OR sic.regex = :regex)",
      nativeQuery = true
   )
   Number existsByNameOrRegex(@Param("name") String var1, @Param("regex") String var2);

   default boolean exists(String name, String regex) {
      return this.existsByNameOrRegex(name, regex).intValue() == 1;
   }
}
