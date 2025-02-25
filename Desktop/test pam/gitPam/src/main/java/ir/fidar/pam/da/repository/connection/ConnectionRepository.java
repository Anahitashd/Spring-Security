package ir.fidar.pam.da.repository.connection;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.connection.Connection;
import ir.fidar.pam.domain.type.ConnectionType;
import java.util.Set;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface ConnectionRepository extends GenericRepository<Connection, Long> {
   Connection findOneByNameIgnoreCase(String var1);

   Connection findOneByTransparentPort(int var1);

   Connection findOneByIpAddressAndPortAndType(String var1, int var2, ConnectionType var3);

   boolean existsByTransparentPort(int var1);

   @Query(
      value = "WITH enabled_cr (id) AS              (SELECT cr.id FROM tb_capture_rule cr WHERE cr.disabled = 0 AND (cr.expiration_time = 0 OR cr.expiration_time > :nowSeconds)),      user_con (id) AS          (SELECT crc.connection_id           FROM tb_capture_rule_user cru               JOIN tb_capture_rule_connection crc ON cru.capture_rule_id = crc.capture_rule_id           WHERE cru.user_id = :uid             AND cru.capture_rule_id IN (SELECT id FROM enabled_cr)),      user_cg (id) AS          (SELECT cgc.connection_id           FROM tb_capture_rule_user cru               JOIN tb_capture_rule_connection_group crcg ON cru.capture_rule_id = crcg.capture_rule_id               JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id           WHERE cru.user_id = :uid             AND cru.capture_rule_id IN (SELECT id FROM enabled_cr)),      ug_con (id) AS          (SELECT crc.connection_id           FROM tb_user_user_group uug               JOIN tb_capture_rule_user_group crug ON uug.user_group_id = crug.user_group_id               JOIN tb_capture_rule_connection crc ON crug.capture_rule_id = crc.capture_rule_id           WHERE uug.user_id = :uid             AND crug.capture_rule_id IN (SELECT id FROM enabled_cr)),      ug_cg (id) AS          (SELECT cgc.connection_id           FROM tb_user_user_group uug               JOIN tb_capture_rule_user_group crug ON uug.user_group_id = crug.user_group_id               JOIN tb_capture_rule_connection_group crcg ON crug.capture_rule_id = crcg.capture_rule_id               JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id           WHERE uug.user_id = :uid             AND crug.capture_rule_id IN (SELECT id FROM enabled_cr)),      accessible_cons (id) AS          (SELECT id           FROM user_con           UNION           SELECT id           FROM user_cg           UNION           SELECT id           FROM ug_con           UNION           SELECT id           FROM ug_cg) SELECT c.name FROM accessible_cons     JOIN (SELECT c.name, c.id FROM tb_connection c) AS c ON accessible_cons.id = c.id",
      nativeQuery = true
   )
   Set<String> allConnectionNamesAccessibleByUser(@Param("uid") long var1, @Param("nowSeconds") long var3);

   @Query(
      value = "SELECT c.* FROM tb_connection c JOIN tb_access_rule_connection arc ON c.id = arc.connection_id WHERE arc.access_rule_id = :ar_id UNION SELECT c.* FROM tb_connection  c   JOIN tb_connection_group_connection cgc ON c.id = cgc.connection_id     JOIN tb_access_rule_connection_group arcg ON cgc.connection_group_id = arcg.connection_group_id WHERE arcg.access_rule_id = :ar_id",
      nativeQuery = true
   )
   Set<Connection> findAllByAccessRuleId(@Param("ar_id") long var1);
}
