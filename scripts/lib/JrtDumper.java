import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

/**
 * JrtDumper - walk the running JVM's jrt:/ filesystem and write each module's
 * classes to a flat JAR.  Run with the container's own JVM:
 *
 *     java -cp /tmp/scripts JrtDumper <out_dir> [module1,module2,...|ALL]
 *
 * Output is one .jar per module (e.g. java.base.jar, jdk.unsupported.jar)
 * with classes at the top level so PrototypeFinal's GetJarPaths can read them
 * without any further repacking.
 *
 * Compiled with --release 9 so the same .class works on JDK 9, 10, 11, ..., 25.
 */
public final class JrtDumper {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JrtDumper <out_dir> [module1,module2,...|ALL]");
            System.exit(2);
        }
        Path outDir = Paths.get(args[0]);
        Files.createDirectories(outDir);

        Set<String> filter = null; // null == ALL
        if (args.length >= 2 && !args[1].equals("ALL") && !args[1].isEmpty()) {
            filter = new HashSet<>(Arrays.asList(args[1].split(",")));
        }

        FileSystem jrt = FileSystems.newFileSystem(URI.create("jrt:/"), Collections.emptyMap());
        Path modulesRoot = jrt.getPath("/modules");

        // Discover module names (the immediate children of /modules).
        List<String> moduleNames;
        try (Stream<Path> children = Files.list(modulesRoot)) {
            moduleNames = children
                    .filter(Files::isDirectory)
                    .map(p -> p.getFileName().toString())
                    .sorted()
                    .collect(java.util.stream.Collectors.toList());
        }

        Map<String, Integer> entryCounts = new HashMap<>();
        int totalModules = 0;
        for (String module : moduleNames) {
            if (filter != null && !filter.contains(module)) continue;
            Path moduleRoot = modulesRoot.resolve(module);
            Path target = outDir.resolve(module + ".jar");

            int written = 0;
            try (OutputStream os = Files.newOutputStream(target);
                 JarOutputStream jout = new JarOutputStream(os);
                 Stream<Path> walker = Files.walk(moduleRoot)) {
                for (Path p : (Iterable<Path>) walker::iterator) {
                    if (!Files.isRegularFile(p)) continue;
                    String entryName = moduleRoot.relativize(p).toString();
                    // Normalise on Windows-style separators if any
                    entryName = entryName.replace('\\', '/');
                    try {
                        jout.putNextEntry(new JarEntry(entryName));
                        Files.copy(p, jout);
                        jout.closeEntry();
                        written++;
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
            }
            entryCounts.put(module, written);
            totalModules++;
        }

        System.out.printf("Wrote %d modules to %s%n", totalModules, outDir);
        for (Map.Entry<String, Integer> e : entryCounts.entrySet()) {
            System.out.printf("  %-30s %5d entries%n", e.getKey(), e.getValue());
        }
    }
}
