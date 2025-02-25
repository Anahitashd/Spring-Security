package ir.fidar.pam.service.impl;

import ir.fidar.pam.da.repository.SymmetricKeyRepository;
import ir.fidar.pam.domain.dto.SymmetricKeyDto;
import ir.fidar.pam.domain.dto.SymmetricKeyRegisterDto;
import ir.fidar.pam.domain.model.SymmetricKey;
import ir.fidar.pam.exception.SymmetricKeyAlreadyRegisteredException;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.service.SymmetricKeyService;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SymmetricKeyServiceImpl implements SymmetricKeyService {
   private static final Logger LOGGER = LogManager.getLogger();
   private final SymmetricKeyRepository symmetricKeyRepository;

   public SymmetricKeyServiceImpl(SymmetricKeyRepository symmetricKeyRepository) {
      this.symmetricKeyRepository = symmetricKeyRepository;
   }

   @Override
   public Optional<SymmetricKeyDto> load() {
      SymmetricKey symmetricKey = (SymmetricKey)this.symmetricKeyRepository.findById(1L).orElse(null);
      if (symmetricKey != null) {
         SymmetricKeyDto symmetricKeyDto = new SymmetricKeyDto();
         symmetricKeyDto.setKey(symmetricKey.getSymmetricKey());
         return Optional.of(symmetricKeyDto);
      } else {
         return Optional.empty();
      }
   }

   @Transactional
   @Override
   public void register(SymmetricKeyRegisterDto symmetricKeyRegisterDto) throws SymmetricKeyAlreadyRegisteredException {
      if (this.symmetricKeyRepository.findById(1L).isPresent()) {
         LOGGER.info(Markers.SYSTEM, "Tried to re-register symmetric key");
         throw new SymmetricKeyAlreadyRegisteredException();
      } else {
         SymmetricKey symmetricKey = new SymmetricKey();
         symmetricKey.setSymmetricKey(symmetricKeyRegisterDto.getKey());
         this.symmetricKeyRepository.save(symmetricKey);
         LOGGER.info(Markers.SYSTEM, "Symmetric key is registered successfully");
      }
   }
}
