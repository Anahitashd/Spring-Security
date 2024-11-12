package ir.fidar.pam.da.repository;

import ir.fidar.pam.domain.model.Banner;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BannerRepository extends JpaRepository<Banner, Long> {
   List<Banner> findAllByConnectionId(Long var1);

   Banner findOneByConnectionIdAndMessage(Long var1, String var2);

   void deleteAllByConnectionId(Long var1);
}
