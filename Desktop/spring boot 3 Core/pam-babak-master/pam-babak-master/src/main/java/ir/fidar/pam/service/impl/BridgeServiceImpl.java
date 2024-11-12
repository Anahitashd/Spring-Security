package ir.fidar.pam.service.impl;

import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.pam.da.repository.BridgeRepository;
import ir.fidar.pam.domain.model.Bridge;
import ir.fidar.pam.service.BridgeService;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class BridgeServiceImpl extends BridgeCrudServiceImpl implements BridgeService {
   private BridgeRepository bridgeRepository;

   public BridgeServiceImpl(BridgeRepository bridgeRepository) {
      super(bridgeRepository);
      this.bridgeRepository = bridgeRepository;
   }

   @Override
   public List<Bridge> getAll() {
      return this.bridgeRepository.findAll();
   }

   public Bridge getOne(String name) {
      return Optional.ofNullable(this.bridgeRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Bridge.class)));
   }

   public Bridge getOne(Long id) {
      return Optional.ofNullable(this.bridgeRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(Bridge.class)));
   }
}
