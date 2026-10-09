import com.mojang.authlib.EnvironmentParser;
import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;
import java.net.Proxy;
import java.io.BufferedReader;
import java.io.InputStreamReader;

// Runs in a separate JVM without Fabric or mods, with the same Authlib JAR and TLS settings.
class AuthlibProbe {
    public static void main(String[] args) {
        try {
            String base = args[0];
            var env = EnvironmentParser.getEnvironmentFromProperties().orElseThrow();
            if (!env.sessionHost().equals(base + "/session") ||
                !env.servicesHost().equals(base + "/services") ||
                !env.profilesHost().equals(base + "/profiles")) throw new Exception();
            String fake = new BufferedReader(new InputStreamReader(System.in)).readLine();
            var auth = new YggdrasilAuthenticationService(Proxy.NO_PROXY);
            auth.createUserApiService(fake).fetchProperties();
            System.out.println("AUTHLIB_PROBE_OK");
        } catch (Throwable error) {
            System.err.println("Authlib custom hosts/TLS/API probe failed (" + error.getClass().getSimpleName() + "). Launch refused.");
            System.exit(2);
        }
    }
}
