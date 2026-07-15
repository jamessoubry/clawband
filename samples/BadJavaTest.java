import org.junit.Test;
import static org.junit.Assert.*;

public class BadJavaTest {

    @Test
    public void testGetLength_nonNull() {
        BadJava bj = new BadJava();
        assertEquals(5, bj.getLength("hello"));
    }

    @Test
    public void testGenerateToken_returnsString() {
        BadJava bj = new BadJava();
        String token = bj.generateToken();
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test(expected = NullPointerException.class)
    public void testGetLength_null_throws() {
        BadJava bj = new BadJava();
        bj.getLength(null);
    }
}
