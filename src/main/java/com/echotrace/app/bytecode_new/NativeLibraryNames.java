package com.echotrace.app.bytecode_new;

import java.io.File;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

final class NativeLibraryNames {
    private NativeLibraryNames() {
    }

    static Map<String, String> fromTargetDir(String targetDir) {
        Map<String, String> resolved = new HashMap<>();
        File libsDir = deriveLibsDir(targetDir);
        if (libsDir == null || !libsDir.isDirectory()) {
            return resolved;
        }

        File[] files = libsDir.listFiles(File::isFile);
        if (files == null) {
            return resolved;
        }

        for (File file : files) {
            String name = file.getName();
            addAliases(resolved, name);
        }
        return resolved;
    }

    static String resolve(String lib, Map<String, String> resolvedNames) {
        if (lib == null || lib.isEmpty() || lib.startsWith("<?>")) {
            return lib;
        }
        if ("<null:default-c-lib>".equals(lib) || "<default>".equals(lib)) {
            return resolvedNames.getOrDefault("c", lib);
        }
        if (lib.contains("|")) {
            StringBuilder out = new StringBuilder();
            for (String part : lib.split("\\|")) {
                if (out.length() > 0) {
                    out.append('|');
                }
                out.append(resolve(part.trim(), resolvedNames));
            }
            return out.toString();
        }
        String key = normalizeKey(lib);
        return resolvedNames.getOrDefault(key, lib);
    }

    private static File deriveLibsDir(String targetDir) {
        File target = new File(targetDir).getAbsoluteFile();
        File parent = target.getParentFile();
        if (parent == null) {
            return null;
        }

        String name = target.getName();
        if (name.startsWith("JARFILES_")) {
            return new File(parent, "LIBS_" + name.substring("JARFILES_".length()));
        }
        return new File(parent, "LIBS_" + name);
    }

    private static void addAliases(Map<String, String> resolved, String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!looksLikeNativeLibrary(lower)) {
            return;
        }

        putIfBetter(resolved, normalizeKey(fileName), fileName);
        putIfBetter(resolved, normalizeKey(System.mapLibraryName(stripKnownNativeSuffix(fileName))), fileName);

        if (lower.startsWith("lib")) {
            String withoutLib = fileName.substring(3);
            int soIndex = withoutLib.indexOf(".so");
            if (soIndex > 0) {
                String stem = withoutLib.substring(0, soIndex);
                putIfBetter(resolved, normalizeKey(stem), fileName);
                int dashIndex = stem.indexOf('-');
                if (dashIndex > 0) {
                    putIfBetter(resolved, normalizeKey(stem.substring(0, dashIndex)), fileName);
                }
            }
            int dylibIndex = withoutLib.indexOf(".dylib");
            if (dylibIndex > 0) {
                putIfBetter(resolved, normalizeKey(withoutLib.substring(0, dylibIndex)), fileName);
            }
        }

        int dllIndex = lower.indexOf(".dll");
        if (dllIndex > 0) {
            putIfBetter(resolved, normalizeKey(fileName.substring(0, dllIndex)), fileName);
        }
    }

    private static boolean looksLikeNativeLibrary(String lowerName) {
        return lowerName.endsWith(".so")
                || lowerName.contains(".so.")
                || lowerName.endsWith(".dylib")
                || lowerName.endsWith(".dll");
    }

    private static String stripKnownNativeSuffix(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.startsWith("lib")) {
            fileName = fileName.substring(3);
            lower = lower.substring(3);
        }
        int soIndex = lower.indexOf(".so");
        if (soIndex > 0) {
            return fileName.substring(0, soIndex);
        }
        int dylibIndex = lower.indexOf(".dylib");
        if (dylibIndex > 0) {
            return fileName.substring(0, dylibIndex);
        }
        int dllIndex = lower.indexOf(".dll");
        if (dllIndex > 0) {
            return fileName.substring(0, dllIndex);
        }
        return fileName;
    }

    private static String normalizeKey(String value) {
        String key = value.trim().toLowerCase(Locale.ROOT);
        if (key.startsWith("lib")) {
            key = key.substring(3);
        }
        int soIndex = key.indexOf(".so");
        if (soIndex > 0) {
            key = key.substring(0, soIndex);
        }
        int dylibIndex = key.indexOf(".dylib");
        if (dylibIndex > 0) {
            key = key.substring(0, dylibIndex);
        }
        int dllIndex = key.indexOf(".dll");
        if (dllIndex > 0) {
            key = key.substring(0, dllIndex);
        }
        return key;
    }

    private static void putIfBetter(Map<String, String> resolved, String key, String fileName) {
        if (key.isEmpty()) {
            return;
        }
        String existing = resolved.get(key);
        if (existing == null || score(fileName) > score(existing)) {
            resolved.put(key, fileName);
        }
    }

    private static int score(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if ("libc.so.6".equals(lower)) {
            return 100;
        }
        if (lower.contains(".so.")) {
            return 80;
        }
        if (lower.endsWith(".so") || lower.endsWith(".dylib") || lower.endsWith(".dll")) {
            return 60;
        }
        return 0;
    }
}
