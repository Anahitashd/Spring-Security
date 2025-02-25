package ir.fidar.pam.da.repository.connection;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.connection.ConnectionGroup;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.EntityGraph.EntityGraphType;
import org.springframework.stereotype.Repository;

@Repository
public interface ConnectionGroupRepository extends GenericRepository<ConnectionGroup, Long> {
   @EntityGraph(
      attributePaths = {"connections"},
      type = EntityGraphType.LOAD
   )
   ConnectionGroup findOneById(Long var1);

   @EntityGraph(
      attributePaths = {"connections"},
      type = EntityGraphType.LOAD
   )
   ConnectionGroup findOneByNameIgnoreCase(String var1);
}
