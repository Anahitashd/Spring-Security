package ir.fidar.pam.service.impl;

import ir.fidar.core.da.core.repository.GenericCrudRepository;
import ir.fidar.core.exception.EntityNotFoundException;
import ir.fidar.core.exception.generic.ResourceNotFoundException;
import ir.fidar.pam.da.repository.SessionInputConstraintRepository;
import ir.fidar.pam.domain.model.SessionInputConstraint;
import ir.fidar.pam.service.SessionInputConstraintService;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class SessionInputConstraintServiceImpl extends SessionInputConstraintCrudServiceImpl implements SessionInputConstraintService {
   private final SessionInputConstraintRepository sessionInputConstraintRepository;

   public SessionInputConstraintServiceImpl(
      SessionInputConstraintRepository sessionInputConstraintRepository, GenericCrudRepository<SessionInputConstraint> sessionInputConstraintcrudRepository
   ) {
      super(sessionInputConstraintRepository, sessionInputConstraintcrudRepository);
      this.sessionInputConstraintRepository = sessionInputConstraintRepository;
   }

   @Override
   public List<SessionInputConstraint> getAll() {
      return this.sessionInputConstraintRepository.findAll();
   }

   public SessionInputConstraint getOne(String name) {
      return Optional.ofNullable(this.sessionInputConstraintRepository.findOneByNameIgnoreCase(name))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionInputConstraint.class)));
   }

   public SessionInputConstraint getOne(Long id) {
      return Optional.ofNullable(this.sessionInputConstraintRepository.findOneById(id))
         .orElseThrow(() -> new ResourceNotFoundException(new EntityNotFoundException(SessionInputConstraint.class)));
   }
}
