package ir.fidar.pam.controller.management;

import ir.fidar.core.management.response.Response;
import ir.fidar.core.security.exception.AccessDeniedException;
import ir.fidar.core.security.service.AuthorizationService;
import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.domain.util.converter.attribbute.connection.ConnectionTypeConverter;
import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.Query;
import jakarta.persistence.Tuple;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/reporting/charts"})
public class ReportingController {
   @Autowired
   private EntityManagerFactory entityManagerFactory;
   @Autowired
   private AuthorizationService authorizationService;
   private final ConnectionTypeConverter connectionTypeConverter = new ConnectionTypeConverter();

   @GetMapping({"/session-type-count"})
   public ResponseEntity<Response> getSessionPerTypeCount() {
      this.authorize();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();

      ResponseEntity var11;
      try {
         Query query = entityManager.createNativeQuery(
            "SELECT c.type, COUNT(c.type) AS `count` FROM tb_connection c     JOIN tb_access_rule_connection arc ON c.id = arc.connection_id GROUP BY c.type UNION ALL SELECT c.type, COUNT(c.type) AS `count` FROM tb_connection c     JOIN tb_connection_group_connection cgc ON c.id = cgc.connection_id     JOIN tb_access_rule_connection_group arcg ON cgc.connection_group_id = arcg.connection_group_id GROUP BY c.type",
            Tuple.class
         );
         query.setHint("org.hibernate.readOnly", true);
         List<Tuple> tuples = query.getResultList();
         int[] result = new int[4];

         for (Tuple tuple : tuples) {
            ConnectionType connectionType = this.connectionTypeConverter
               .convertToEntityAttribute(Integer.valueOf(((Number)tuple.get("type", Number.class)).intValue()));
            switch (connectionType) {
               case SSH:
                  result[0] = ((Number)tuple.get("count", Number.class)).intValue();
                  break;
               case RDP:
                  result[1] = ((Number)tuple.get("count", Number.class)).intValue();
                  break;
               case VNC:
                  result[2] = ((Number)tuple.get("count", Number.class)).intValue();
                  break;
               case TELNET:
                  result[3] = ((Number)tuple.get("count", Number.class)).intValue();
            }
         }

         var11 = ResponseEntity.ok(Response.Crud.get(result));
      } finally {
         entityManager.close();
      }

      return var11;
   }

   @GetMapping({"/connection-type-count"})
   public ResponseEntity getConnectionPerTypeCount() {
      this.authorize();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();
      Query query = entityManager.createQuery("select c.type, count(c.type) from Connection c group by c.type", Tuple.class);
      query.setHint("org.hibernate.readOnly", true);
      List<Tuple> tuples = query.getResultList();
      long[] result = new long[4];

      for (Tuple tuple : tuples) {
         ConnectionType connectionType = (ConnectionType)tuple.get(0);
         Long count = Long.valueOf(tuple.get(1).toString());
         switch (connectionType) {
            case SSH:
               result[0] = count;
               break;
            case RDP:
               result[1] = count;
               break;
            case VNC:
               result[2] = count;
               break;
            case TELNET:
               result[3] = count;
         }
      }

      entityManager.close();
      return ResponseEntity.ok(Response.Crud.get(result));
   }

   @GetMapping({"/established-session-type-count"})
   public ResponseEntity getEstablishedSessionPerTypeCount() {
      this.authorize();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();
      Query query = entityManager.createQuery("select c.type, count(c.type) from Capture c group by c.type", Tuple.class);
      query.setHint("org.hibernate.readOnly", true);
      List<Tuple> tuples = query.getResultList();
      long[] result = new long[4];

      for (Tuple tuple : tuples) {
         ConnectionType connectionType = (ConnectionType)tuple.get(0);
         Long count = Long.valueOf(tuple.get(1).toString());
         switch (connectionType) {
            case SSH:
               result[0] = count;
               break;
            case RDP:
               result[1] = count;
               break;
            case VNC:
               result[2] = count;
               break;
            case TELNET:
               result[3] = count;
         }
      }

      entityManager.close();
      return ResponseEntity.ok(Response.Crud.get(result));
   }

   @GetMapping({"/five-active-connections"})
   public ResponseEntity getFiveMostActiveConnections() {
      this.authorize();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();
      Query query = entityManager.createQuery(
         "select c.type as type, c.connectionName as name, count(c.type) as s from Capture c group by c.type, c.connectionName order by s DESC", Tuple.class
      );
      query.setHint("org.hibernate.readOnly", true);
      query.setFirstResult(0);
      query.setMaxResults(5);
      List<Tuple> tuples = query.getResultList();
      List<MostActiveConnectionsDto> mostActiveConnectionsDtoList = new ArrayList<>();

      for (Tuple tuple : tuples) {
         MostActiveConnectionsDto mostActiveConnectionsDto = new MostActiveConnectionsDto();
         mostActiveConnectionsDto.setName((String)tuple.get(1));
         mostActiveConnectionsDto.setType((ConnectionType)tuple.get(0));
         mostActiveConnectionsDto.setCount(Long.valueOf(tuple.get(2).toString()).intValue());
         mostActiveConnectionsDtoList.add(mostActiveConnectionsDto);
      }

      entityManager.close();
      return ResponseEntity.ok(Response.Crud.get(mostActiveConnectionsDtoList));
   }

   @GetMapping({"/five-active-users"})
   public ResponseEntity getFiveMostActiveUsers() {
      this.authorize();
      EntityManager entityManager = this.entityManagerFactory.createEntityManager();
      Query query = entityManager.createQuery("select c.owner as owner, count(c.owner) as s from Capture c group by c.owner order by s DESC", Tuple.class);
      query.setHint("org.hibernate.readOnly", true);
      query.setFirstResult(0);
      query.setMaxResults(5);
      List<Tuple> tuples = query.getResultList();
      List<MostActiveUsersDto> mostActiveUsersDtoList = new ArrayList<>();

      for (Tuple tuple : tuples) {
         MostActiveUsersDto activeConnectionsDto = new MostActiveUsersDto();
         activeConnectionsDto.setUsername((String)tuple.get(0));
         activeConnectionsDto.setSessionCount(Integer.parseInt(tuple.get(1).toString()));
         mostActiveUsersDtoList.add(activeConnectionsDto);
      }

      entityManager.close();
      return ResponseEntity.ok(Response.Crud.get(mostActiveUsersDtoList));
   }

   private void authorize() {
      if (!this.authorizationService.getCurrentUserInfo().getRole().equalsIgnoreCase("SUPERUSER")) {
         throw new AccessDeniedException();
      }
   }
}
