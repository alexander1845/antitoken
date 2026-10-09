import com.mojang.authlib.EnvironmentParser;
import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;
import java.net.Proxy;

// Runs in the same sandbox as the game, without mods, with the same Authlib JAR and TLS settings.
// args[1] is the session's FAKE token (worthless outside the vault), never a real credential.
class AuthlibProbe {
    public static void main(String[] args) {
        try {
            String base = args[0];
            var env = EnvironmentParser.getEnvironmentFromProperties().orElseThrow();
            // Authlib 6 has no profiles host; newer builds do. Check whichever this build has.
            if (!host(env, "sessionHost").equals(base + "/session") || !host(env, "servicesHost").equals(base + "/services"))
                throw new Exception("Authlib ignored the custom hosts");
            String profiles = host(env, "profilesHost");
            if (profiles != null && !profiles.equals(base + "/profiles")) throw new Exception("Authlib ignored the profiles host");
            String fake = args[1];
            var auth = new YggdrasilAuthenticationService(Proxy.NO_PROXY);
            auth.createUserApiService(fake).fetchProperties();
            System.out.println("AUTHLIB_PROBE_OK");
            System.exit(0); // The launcher reads only the exit code; output goes to its capture file.
        } catch (Throwable error) {
            // Printed to the launcher's capture file; contains the fake token at most, never a real credential.
            error.printStackTrace();
            System.err.println("Authlib custom hosts/TLS/API probe failed (" + error.getClass().getSimpleName() + "). Launch refused.");
            System.exit(2);
        }
    }

    private static String host(Object env, String name) throws Exception {
        try { return (String) env.getClass().getMethod(name).invoke(env); }
        catch (NoSuchMethodException missing) { return null; }
    }
}
