package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.management.Markers;
import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reflections.Reflections;
import org.reflections.scanners.Scanner;
import org.reflections.scanners.SubTypesScanner;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Service;

@Service
public class ProcessorChainInstructionProcessingService implements InstructionProcessingService, InitializingBean, ApplicationContextAware {
   private static final Logger LOGGER = LogManager.getLogger();
   private static final Map<ConnectionType, List<InstructionProcessor>> SESSION_BASED_INSTRUCTION_PROCESSORS = new HashMap<ConnectionType, List<InstructionProcessor>>(
      
   ) {
      @Override
      public String toString() {
         StringBuilder stringBuilder = new StringBuilder();

         for (ConnectionType connectionType : ProcessorChainInstructionProcessingService.SESSION_BASED_INSTRUCTION_PROCESSORS.keySet()) {
            if (stringBuilder.length() > 0) {
               stringBuilder.append(", ");
            }

            stringBuilder.append(connectionType)
               .append(": ")
               .append(this.get(connectionType).stream().map(c -> c.getClass().getSimpleName()).collect(Collectors.toList()));
         }

         return stringBuilder.toString();
      }
   };
   private ApplicationContext applicationContext;

   public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
      this.applicationContext = applicationContext;
   }

   public void afterPropertiesSet() throws Exception {
      Reflections reflections = new Reflections(this.getClass().getPackage().getName(), new Scanner[]{new SubTypesScanner()});

      for (ConnectionType connectionType : ConnectionType.values()) {
         SESSION_BASED_INSTRUCTION_PROCESSORS.put(connectionType, new ArrayList<>());
      }

      for (Class<? extends OrderedSessionTypeAwareInstructionProcessor> instructionProcessorClass : reflections.getSubTypesOf(
         OrderedSessionTypeAwareInstructionProcessor.class
      )) {
         if (!Modifier.isAbstract(instructionProcessorClass.getModifiers())) {
            OrderedSessionTypeAwareInstructionProcessor instructionProcessor = this.createInstance(instructionProcessorClass);
            if (instructionProcessor.getSessionTypes().isEmpty()) {
               for (ConnectionType connectionType : SESSION_BASED_INSTRUCTION_PROCESSORS.keySet()) {
                  SESSION_BASED_INSTRUCTION_PROCESSORS.get(connectionType).add(instructionProcessor);
               }
            } else {
               for (Object sessionType : instructionProcessor.getSessionTypes()) {
                  SESSION_BASED_INSTRUCTION_PROCESSORS.get(sessionType).add(instructionProcessor);
               }
            }
         }
      }

      ProcessorChainInstructionProcessingService.InstructionProcessorComparator comparator = new ProcessorChainInstructionProcessingService.InstructionProcessorComparator(
         
      );

      for (ConnectionType connectionType : SESSION_BASED_INSTRUCTION_PROCESSORS.keySet()) {
         Collections.sort(SESSION_BASED_INSTRUCTION_PROCESSORS.get(connectionType), comparator);
      }

      LOGGER.debug(Markers.SESSION, "Instruction processors are retrieved as: {}", SESSION_BASED_INSTRUCTION_PROCESSORS.toString());
   }

   @Override
   public void process(GuacamoleInstruction instruction, InputSource source, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      for (InstructionProcessor instructionProcessor : SESSION_BASED_INSTRUCTION_PROCESSORS.get(
         remoteSessionInputExtraction.getUnderlyingConnection().getType()
      )) {
         if (instructionProcessor.processInput(instruction, source, remoteSessionInputExtraction)) {
            break;
         }
      }
   }

   private OrderedSessionTypeAwareInstructionProcessor createInstance(Class<? extends OrderedSessionTypeAwareInstructionProcessor> instructionProcessorClass) throws InstantiationException, IllegalAccessException, InvocationTargetException {
      if (instructionProcessorClass.getDeclaredConstructors().length <= 0) {
         return instructionProcessorClass.newInstance();
      } else {
         Constructor constructor = instructionProcessorClass.getDeclaredConstructors()[0];
         Object[] parameters = new Object[constructor.getParameterCount()];

         for (int i = 0; i < constructor.getParameterCount(); i++) {
            parameters[i] = this.applicationContext.getBean(constructor.getParameterTypes()[i]);
         }

         return (OrderedSessionTypeAwareInstructionProcessor)constructor.newInstance(parameters);
      }
   }

   private static class InstructionProcessorComparator<T extends Ordered> implements Comparator<T> {
      private InstructionProcessorComparator() {
      }

      public int compare(T o1, T o2) {
         return Integer.compare(o1.getOrder(), o2.getOrder());
      }
   }
}
