package ir.fidar.pam.session.filters;

import ir.fidar.core.exception.SystemInternalErrorException;
import ir.fidar.pam.domain.model.SessionInputConstraintViolationHandler;
import ir.fidar.pam.session.exception.SessionInputValidationException;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.springframework.util.Assert;

public class CachedBufferSessionInputSessionInputValidator implements SessionInputValidator {
    private static final int PATTERN_MATCH_EXECUTION_TIMEOUT_SECOND = 2;

    private final Set<PatternHandlerMapper> patternHandlerMapperSet;

    private final StringBuilder buffer;

    private final BufferCache bufferCache;

    public CachedBufferSessionInputSessionInputValidator(Set<SessionInputConstraintViolationHandler> handlers) {
        Assert.notNull(handlers, " Handlers set can not be null");
        Assert.notEmpty(handlers, " Handlers set can not be empty");
        this.patternHandlerMapperSet = new HashSet<>();
        for (SessionInputConstraintViolationHandler handler : handlers)
            this.patternHandlerMapperSet.add(new PatternHandlerMapper(

                    Pattern.compile(handler.getInputConstraint().getRegex()), handler));
        this.buffer = new StringBuilder();
        this.bufferCache = new BufferCache();
    }

    public void validate(GuacamoleInstruction instruction) throws Exception {
        synchronized (this) {
            try {
                if (this.patternHandlerMapperSet != null) {
                    int key = Integer.parseInt(instruction.getArgs().get(0));
                    if (key == 65293) {
                        SessionInputValidationException exception = null;
                        String content = this.buffer.toString();
                        for (PatternHandlerMapper patternHandlerMapper : this.patternHandlerMapperSet) {
                            CharSequenceWrapper charSequenceWrapper = new CharSequenceWrapper(content, Instant.now().getEpochSecond(), 2);
                            boolean matched = false;
                            try {
                                matched = patternHandlerMapper.getPattern().matcher(charSequenceWrapper).matches();
                            } catch (Exception exception1) {

                            } finally {
                                if (matched)
                                    exception = new SessionInputValidationException(patternHandlerMapper.getHandler(), content);
                            }
                            if (exception != null)
                                break;
                        }
                        this.buffer.setLength(0);
                        if (exception != null)
                            throw exception;
                    } else if (key == 65288) {
                        if (this.buffer.length() > 0)
                            this.buffer.delete(this.buffer.length() - 1, this.buffer.length());
                    } else if (key != 65289) {
                        this.buffer.append((char)key);
                    }
                }
            } catch (SessionInputValidationException e) {
                throw e;
            } catch (Exception e) {
                throw new SystemInternalErrorException(e);
            }
        }
    }

    private static class PatternHandlerMapper {
        private final Pattern pattern;

        private final SessionInputConstraintViolationHandler handler;

        private PatternHandlerMapper(Pattern pattern, SessionInputConstraintViolationHandler handler) {
            this.pattern = pattern;
            this.handler = handler;
        }

        public Pattern getPattern() {
            return this.pattern;
        }

        public SessionInputConstraintViolationHandler getHandler() {
            return this.handler;
        }

        public boolean equals(Object o) {
            if (this == o)
                return true;
            if (o == null || getClass() != o.getClass())
                return false;
            PatternHandlerMapper that = (PatternHandlerMapper)o;
            return this.pattern.pattern().equals(that.pattern.pattern());
        }

        public int hashCode() {
            return Objects.hash(new Object[] { this.pattern.pattern() });
        }
    }

    private static class CharSequenceWrapper implements CharSequence {
        private final CharSequence charSequence;

        private final long initialTime;

        private final int timeout;

        private CharSequenceWrapper(CharSequence charSequence, long initialTime, int timeout) {
            Assert.notNull(charSequence, "charSequence must not be null");
            this.charSequence = charSequence;
            this.initialTime = initialTime;
            this.timeout = timeout;
        }

        public int length() {
            return this.charSequence.length();
        }

        public char charAt(int index) {
            checkIfThreadInterrupted();
            return this.charSequence.charAt(index);
        }

        public CharSequence subSequence(int start, int end) {
            checkIfThreadInterrupted();
            return new CharSequenceWrapper(this.charSequence.subSequence(start, end), this.initialTime, this.timeout);
        }

        public IntStream chars() {
            checkIfThreadInterrupted();
            return this.charSequence.chars();
        }

        public IntStream codePoints() {
            checkIfThreadInterrupted();
            return this.charSequence.codePoints();
        }

        public String toString() {
            return this.charSequence.toString();
        }

        private void checkIfThreadInterrupted() {
            if (Instant.now().getEpochSecond() - this.initialTime >= this.timeout)
                throw new RuntimeException(new InterruptedException());
        }
    }

    private static class BufferCache {
        private static final int MAX_CACHE_SIZE = 25;

        private BufferCache() {}

        private static Map<String, Integer> CONTENT_RESULT_ARRAY_INDEX_MAPPER = new HashMap<>(25);

        private static CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult[] CACHED_BUFFER_PROCESS_RESULT = new CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult[25];

        private static int counter = 0;

        public void add(String content, Exception exception) {
            int index = ((Integer)CONTENT_RESULT_ARRAY_INDEX_MAPPER.getOrDefault(content, Integer.valueOf(-1))).intValue();
            if (index == -1) {
                if (counter == 25) {
                    int minLastAccessTimeIndex = 0;
                    long minLastAccessTime = CACHED_BUFFER_PROCESS_RESULT[minLastAccessTimeIndex].getLastAccessTime();
                    for (int i = 1; i < CACHED_BUFFER_PROCESS_RESULT.length; i++) {
                        long lastAccessTime = CACHED_BUFFER_PROCESS_RESULT[i].getLastAccessTime();
                        if (lastAccessTime < minLastAccessTime) {
                            minLastAccessTime = lastAccessTime;
                            minLastAccessTimeIndex = i;
                        }
                    }
                    CONTENT_RESULT_ARRAY_INDEX_MAPPER.remove(CACHED_BUFFER_PROCESS_RESULT[minLastAccessTimeIndex].getBuffer());
                    CONTENT_RESULT_ARRAY_INDEX_MAPPER.put(content, Integer.valueOf(minLastAccessTimeIndex));
                    CACHED_BUFFER_PROCESS_RESULT[minLastAccessTimeIndex] = new CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult(content, exception);
                } else {
                    CACHED_BUFFER_PROCESS_RESULT[counter] = new CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult(content, exception);
                    CONTENT_RESULT_ARRAY_INDEX_MAPPER.put(content, Integer.valueOf(counter));
                    counter = counter++;
                }
            } else {
                CACHED_BUFFER_PROCESS_RESULT[index] = new CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult(content, exception);
            }
        }

        public CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult getProcessResult(String buffer) {
            int index = ((Integer)CONTENT_RESULT_ARRAY_INDEX_MAPPER.getOrDefault(buffer, Integer.valueOf(-1))).intValue();
            if (index == -1)
                return null;
            CachedBufferSessionInputSessionInputValidator.BufferPatternMatchResult matchResult = CACHED_BUFFER_PROCESS_RESULT[index];
            matchResult.updateLastAccessTime();
            return matchResult;
        }
    }

    private static class BufferPatternMatchResult {
        private final String buffer;

        private final Exception exception;

        private long lastAccessTime;

        private BufferPatternMatchResult(String buffer, Exception exception) {
            this.buffer = buffer;
            this.exception = exception;
            this.lastAccessTime = Instant.now().getEpochSecond();
        }

        public String getBuffer() {
            return this.buffer;
        }

        public Exception getException() {
            return this.exception;
        }

        public long getLastAccessTime() {
            return this.lastAccessTime;
        }

        public void updateLastAccessTime() {
            this.lastAccessTime = Instant.now().getEpochSecond();
        }
    }
}
