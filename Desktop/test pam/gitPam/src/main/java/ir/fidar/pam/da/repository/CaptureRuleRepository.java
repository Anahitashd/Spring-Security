package ir.fidar.pam.da.repository;

import ir.fidar.core.da.core.repository.spring.GenericRepository;
import ir.fidar.pam.domain.model.CaptureRule;
import java.util.List;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface CaptureRuleRepository extends GenericRepository<CaptureRule, Long> {
   CaptureRule findOneByName(String var1);

   @Query(
      value = "SELECT (SELECT DISTINCT COUNT(cru.user_id) FROM tb_capture_rule_user cru INNER JOIN tb_capture_rule c on c.id=cru.capture_rule_id WHERE c.name=:name) as users_count, (SELECT DISTINCT COUNT(uug.user_id) FROM tb_user_user_group uug WHERE uug.user_group_id IN (SELECT crug.user_group_id FROM tb_capture_rule_user_group crug INNER JOIN tb_capture_rule c on c.id=crug.capture_rule_id WHERE c.name=:name)) as user_groups_user_count, (SELECT DISTINCT COUNT(crc.connection_id) FROM tb_capture_rule_connection crc INNER JOIN tb_capture_rule c on c.id=crc.capture_rule_id WHERE c.name=:name) as connections_count, (SELECT DISTINCT COUNT(cgc.connection_id) FROM tb_connection_group_connection cgc WHERE cgc.connection_group_id IN (SELECT crcg.connection_group_id FROM tb_capture_rule_connection_group crcg INNER JOIN tb_capture_rule c on c.id=crcg.capture_rule_id WHERE c.name=:name)) as connection_groups_connection_count",
      nativeQuery = true
   )
   List<Object[]> countConnectionsAndUsersByName(@Param("name") String var1);

   @Query(
      value = "WITH enabled_cr (id) AS (    SELECT cr.id    FROM tb_capture_rule cr     WHERE cr.disabled = 0 AND (cr.expiration_time = 0 OR cr.expiration_time > :expThreshold)),user_con (id) AS (    SELECT cru.capture_rule_id     FROM tb_capture_rule_user cru     JOIN enabled_cr ecr ON cru.user_id = :uid AND cru.capture_rule_id = ecr.id     JOIN tb_capture_rule_connection crc ON ecr.id= crc.capture_rule_id AND crc.connection_id = :conId),user_cg (id) AS (    SELECT cru.capture_rule_id     FROM tb_capture_rule_user cru     JOIN enabled_cr ecr ON cru.user_id = :uid AND cru.capture_rule_id = ecr.id     JOIN tb_capture_rule_connection_group crcg ON ecr.id = crcg.capture_rule_id     JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id AND cgc.connection_id = :conId),ug_con (id) AS (    SELECT crug.capture_rule_id     FROM tb_user_user_group uug     JOIN tb_capture_rule_user_group crug ON uug.user_id = :uid AND uug.user_group_id = crug.user_group_id     JOIN enabled_cr ecr ON crug.capture_rule_id = ecr.id     JOIN tb_capture_rule_connection crc ON ecr.id = crc.capture_rule_id AND crc.connection_id = :conId),ug_cg (id) AS (    SELECT crug.capture_rule_id     FROM tb_user_user_group uug     JOIN tb_capture_rule_user_group crug ON uug.user_id = :uid AND uug.user_group_id = crug.user_group_id     JOIN enabled_cr ecr ON crug.capture_rule_id = ecr.id     JOIN tb_capture_rule_connection_group crcg ON ecr.id = crcg.capture_rule_id     JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id AND cgc.connection_id = :conId)SELECT cr.* FROM tb_capture_rule cr JOIN (    SELECT id FROM user_con    UNION    SELECT id FROM user_cg WHERE NOT EXISTS (SELECT id FROM user_con)    UNION    SELECT id FROM ug_con WHERE NOT EXISTS (SELECT id FROM user_cg)    UNION    SELECT id FROM ug_cg WHERE NOT EXISTS (SELECT id FROM ug_con)) AS uc ON cr.id = uc.id",
      nativeQuery = true
   )
   CaptureRule findOneByUserIdAndConnectionId(@Param("uid") Long var1, @Param("conId") Long var2, @Param("expThreshold") Long var3);

   @Query(
      value = "WITH user_con (id) AS (    SELECT cru.capture_rule_id     FROM tb_capture_rule_user cru     JOIN tb_capture_rule_connection crc ON cru.user_id = :uid AND cru.capture_rule_id= crc.capture_rule_id AND crc.connection_id = :conId),user_cg (id) AS (    SELECT cru.capture_rule_id     FROM tb_capture_rule_user cru     JOIN tb_capture_rule_connection_group crcg ON cru.user_id = :uid AND cru.capture_rule_id = crcg.capture_rule_id     JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id AND cgc.connection_id = :conId),ug_con (id) AS (    SELECT crug.capture_rule_id     FROM tb_user_user_group uug     JOIN tb_capture_rule_user_group crug ON uug.user_id = :uid AND uug.user_group_id = crug.user_group_id     JOIN tb_capture_rule_connection crc ON crug.capture_rule_id = crc.capture_rule_id AND crc.connection_id = :conId),ug_cg (id) AS (    SELECT crug.capture_rule_id     FROM tb_user_user_group uug     JOIN tb_capture_rule_user_group crug ON uug.user_id = :uid AND uug.user_group_id = crug.user_group_id     JOIN tb_capture_rule_connection_group crcg ON crug.capture_rule_id = crcg.capture_rule_id     JOIN tb_connection_group_connection cgc ON crcg.connection_group_id = cgc.connection_group_id AND cgc.connection_id = :conId)SELECT cr.* FROM tb_capture_rule cr JOIN (    SELECT id FROM user_con    UNION    SELECT id FROM user_cg WHERE NOT EXISTS (SELECT id FROM user_con)    UNION    SELECT id FROM ug_con WHERE NOT EXISTS (SELECT id FROM user_cg)    UNION    SELECT id FROM ug_cg WHERE NOT EXISTS (SELECT id FROM ug_con)) AS uc ON cr.id = uc.id",
      nativeQuery = true
   )
   CaptureRule findOneByUserIdAndConnectionId(@Param("uid") Long var1, @Param("conId") Long var2);
}
