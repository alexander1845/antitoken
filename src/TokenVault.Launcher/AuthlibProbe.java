import com.mojang.authlib.EnvironmentParser;
import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;
import java.net.Proxy;

// Runs in the same sandbox as the game, without Fabric or mods, with the same Authlib JAR and TLS settings.
// args[1] is the session's FAKE token (worthless outside the vault), never a real credential.
class AuthlibProbe {
    public static void main(String[] args) {
        try {
            String base = args[0];
            var env = EnvironmentParser.getEnvironmentFromProperties().orElseThrow();
            if (!env.sessionHost().equals(base + "/session") ||
                !env.servicesHost().equals(base + "/services") ||
                !env.profilesHost().equals(base + "/profiles")) throw new Exception();
            String fake = args[1];
            var auth = new YggdrasilAuthenticationService(Proxy.NO_PROXY);
            auth.createUserApiService(fake).fetchProperties();
            System.out.println("AUTHLIB_PROBE_OK");
            System.exit(0); // The launcher reads only the exit code; the sandbox gets no output pipe.
        } catch (Throwable error) {
            System.err.println("Authlib custom hosts/TLS/API probe failed (" + error.getClass().getSimpleName() + "). Launch refused.");
            System.exit(2);
        }
    }
}
