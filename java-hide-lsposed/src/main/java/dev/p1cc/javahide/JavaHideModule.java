package dev.p1cc.javahide;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

public final class JavaHideModule implements IXposedHookLoadPackage {
    private static final String TAG = "JavaHide: ";

    private static final String[] TARGET_PACKAGES = {
            "com.bochk.app.aos",
            "com.paic.mo.client"
    };

    private static final String[] HIDDEN_TOKENS = {
            "de.robv.android.xposed",
            "xposedbridge",
            "xposedhelpers",
            "xposed",
            "org.lsposed",
            "lsposed",
            "com.hhvvg.anydebug",
            "anydebug",
            "com.highcapable.yukihookapi",
            "yukihook",
            "me.weishu.epic",
            "libxposed",
            "libxposed_art",
            "edxposed",
            "riru",
            "zygisk"
    };

    private static final ThreadLocal<Boolean> INTERNAL = new ThreadLocal<Boolean>();
    private static volatile boolean active;
    private static volatile ClassLoader cleanAppClassLoader;
    private static volatile String cleanAppSourceDir;
    private static volatile String cleanNativeLibraryDir;
    private static int hiddenLogCount;

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || !isTargetPackage(lpparam.packageName)) {
            return;
        }

        active = false;
        String appSourceDir = null;
        installStackTraceHooks();
        installClassLookupHooks(lpparam.classLoader);
        installClassLoaderSurfaceHooks(appSourceDir);
        installContextClassLoaderHooks();
        installIntentHooks();
        installLibXloaderReportHook(lpparam.classLoader);
        installActivationHook();
        XposedBridge.log(TAG + "installed for " + lpparam.packageName + " / " + lpparam.processName);
    }

    private static void installActivationHook() {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> appClass = Class.forName("android.app.Application");
                Class<?> contextClass = Class.forName("android.content.Context");
                Method attach = appClass.getDeclaredMethod("attach", contextClass);
                attach.setAccessible(true);
                XposedBridge.hookMethod(attach, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        active = true;
                        if (param.args != null && param.args.length > 0) {
                            installCleanClassLoader(param.args[0]);
                        }
                        XposedBridge.log(TAG + "activated before Application.attach");
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        active = true;
                    }
                });
            }
        });
    }

    private static void installContextClassLoaderHooks() {
        hookReturnCleanClassLoader("android.app.ContextImpl", "getClassLoader");
        hookReturnCleanClassLoader("android.content.ContextWrapper", "getClassLoader");

        hookMethods(Class.class, "getClassLoader", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (!active || cleanAppClassLoader == null || !(param.thisObject instanceof Class)) {
                    return;
                }
                Object result = param.getResult();
                String className = ((Class) param.thisObject).getName();
                if (result instanceof ClassLoader
                        && isTargetAppClassName(className)
                        && result != cleanAppClassLoader) {
                    logHidden("Class.getClassLoader", className);
                    param.setResult(cleanAppClassLoader);
                }
            }
        });

        hookMethods(ClassLoader.class, "getParent", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (!active || cleanAppClassLoader == null || !(param.thisObject instanceof ClassLoader)) {
                    return;
                }
                if (classLoaderLooksInjected((ClassLoader) param.thisObject)) {
                    Object cleanParent = cleanAppClassLoader.getParent();
                    if (cleanParent != null) {
                        logHidden("ClassLoader.getParent", String.valueOf(param.thisObject));
                        param.setResult(cleanParent);
                    }
                }
            }
        });
    }

    private static void hookReturnCleanClassLoader(final String className, final String methodName) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> type = Class.forName(className);
                hookMethods(type, methodName, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        if (!active || cleanAppClassLoader == null) {
                            return;
                        }
                        Object result = param.getResult();
                        if (result instanceof ClassLoader && classLoaderLooksInjected((ClassLoader) result)) {
                            logHidden(className + "." + methodName, String.valueOf(result));
                            param.setResult(cleanAppClassLoader);
                        }
                    }
                });
            }
        });
    }

    private static void installCleanClassLoader(Object context) {
        if (context == null || cleanAppClassLoader != null) {
            return;
        }
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Object appInfo = invokeNoArg(context, "getApplicationInfo");
                String sourceDir = stringField(appInfo, "sourceDir");
                String nativeLibraryDir = stringField(appInfo, "nativeLibraryDir");
                if (sourceDir == null || sourceDir.length() == 0) {
                    return;
                }

                Class<?> pathClassLoaderClass = Class.forName("dalvik.system.PathClassLoader");
                Object clean = pathClassLoaderClass
                        .getConstructor(String.class, String.class, ClassLoader.class)
                        .newInstance(sourceDir, nativeLibraryDir, ClassLoader.getSystemClassLoader().getParent());
                if (!(clean instanceof ClassLoader)) {
                    return;
                }

                cleanAppSourceDir = sourceDir;
                cleanNativeLibraryDir = nativeLibraryDir;
                cleanAppClassLoader = (ClassLoader) clean;
                Thread.currentThread().setContextClassLoader(cleanAppClassLoader);

                Object loadedApk = fieldValue(context, "mPackageInfo");
                if (loadedApk != null) {
                    setFieldValue(loadedApk, "mClassLoader", cleanAppClassLoader);
                }
                setFieldValue(context, "mClassLoader", cleanAppClassLoader);
                XposedBridge.log(TAG + "clean classloader installed source=" + sourceDir);
            }
        });
    }

    private static void installIntentHooks() {
        hookIntentStarter("android.app.ContextImpl", "startActivity");
        hookIntentStarter("android.content.ContextWrapper", "startActivity");
        hookIntentStarter("android.app.Activity", "startActivity");
        hookIntentStarter("android.app.Activity", "startActivityForResult");
        hookIntentStarter("android.app.ContextImpl", "startActivities");
        hookIntentStarter("android.content.ContextWrapper", "startActivities");
        hookIntentStarter("android.app.Activity", "startActivities");
    }

    private static void hookIntentStarter(final String className, final String methodName) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> type = Class.forName(className);
                hookMatchingMethods(type, methodName, new MethodMatcher() {
                    @Override
                    public boolean matches(Method method) {
                        Class<?>[] parameterTypes = method.getParameterTypes();
                        return parameterTypes.length > 0 && isIntentOrIntentArray(parameterTypes[0]);
                    }
                }, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        if (!active || param.args == null || param.args.length == 0) {
                            return;
                        }
                        if (shouldBlockIntentObject(param.args[0])) {
                            XposedBridge.log(TAG + "block " + className + "." + methodName + " " + safeLogValue(String.valueOf(param.args[0])));
                            param.setResult(null);
                        }
                    }
                });
            }
        });
    }

    private static void installClassLookupHooks(ClassLoader appClassLoader) {
        hookClassForNameSimple(appClassLoader);
        hookClassForNameWithExplicitLoader();

        hookMethods(ClassLoader.class, "loadClass", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String name = stringArg(param, 0);
                if (shouldHideLookup(name)) {
                    logHidden("ClassLoader.loadClass", name);
                    param.setThrowable(new ClassNotFoundException(name));
                }
            }
        });
    }

    private static void installClassLoaderSurfaceHooks(final String appSourceDir) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> baseDexClassLoader = Class.forName("dalvik.system.BaseDexClassLoader");
                hookMethods(baseDexClassLoader, "toString", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (active && result instanceof String && containsHiddenToken((String) result)) {
                            logHidden("BaseDexClassLoader.toString", (String) result);
                            param.setResult(sanitizedClassLoaderString(param.thisObject, appSourceDir));
                        }
                    }
                });

                Class<?> dexPathList = Class.forName("dalvik.system.DexPathList");
                hookMethods(dexPathList, "toString", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (active && result instanceof String && containsHiddenToken((String) result)) {
                            logHidden("DexPathList.toString", (String) result);
                            param.setResult("DexPathList[[" + replacementPath(appSourceDir) + "]]");
                        }
                    }
                });

                Class<?> dexFile = Class.forName("dalvik.system.DexFile");
                hookMethods(dexFile, "getName", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (active && result instanceof String && containsHiddenToken((String) result)) {
                            logHidden("DexFile.getName", (String) result);
                            param.setResult(replacementPath(appSourceDir));
                        }
                    }
                });
            }
        });

        hookMethods(Field.class, "get", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                if (!active || isInternal() || !(param.thisObject instanceof Field)) {
                    return;
                }
                Field field = (Field) param.thisObject;
                Object result = param.getResult();
                if (!shouldSanitizeFieldResult(field, result)) {
                    return;
                }
                Object sanitized = sanitizeFieldResult(result, appSourceDir);
                if (sanitized != result) {
                    logHidden("Field.get", field.toString());
                    param.setResult(sanitized);
                }
            }
        });
    }

    private static void hookClassForNameSimple(final ClassLoader appClassLoader) {
        hookMatchingMethods(Class.class, "forName", new MethodMatcher() {
            @Override
            public boolean matches(Method method) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                return parameterTypes.length == 1 && parameterTypes[0] == String.class;
            }
        }, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String name = stringArg(param, 0);
                if (name == null || isInternal()) {
                    return;
                }
                if (active && containsHiddenToken(name)) {
                    logHidden("Class.forName", name);
                    param.setThrowable(new ClassNotFoundException(name));
                    return;
                }
                resolveClassForNameWithAppLoader(param, name, appClassLoader);
            }
        });
    }

    private static void hookClassForNameWithExplicitLoader() {
        hookMatchingMethods(Class.class, "forName", new MethodMatcher() {
            @Override
            public boolean matches(Method method) {
                Class<?>[] parameterTypes = method.getParameterTypes();
                return parameterTypes.length == 3
                        && parameterTypes[0] == String.class
                        && parameterTypes[1] == Boolean.TYPE
                        && ClassLoader.class.isAssignableFrom(parameterTypes[2]);
            }
        }, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                String name = stringArg(param, 0);
                if (shouldHideLookup(name)) {
                    logHidden("Class.forName(loader)", name);
                    param.setThrowable(new ClassNotFoundException(name));
                }
            }
        });
    }

    private static void installStackTraceHooks() {
        hookMethods(Throwable.class, "getStackTrace", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (active && result instanceof StackTraceElement[]) {
                    param.setResult(filterStackTrace((StackTraceElement[]) result));
                }
            }
        });

        hookMethods(Thread.class, "getStackTrace", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (active && result instanceof StackTraceElement[]) {
                    param.setResult(filterStackTrace((StackTraceElement[]) result));
                }
            }
        });

        hookMethods(Thread.class, "getAllStackTraces", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (active && result instanceof Map) {
                    param.setResult(filterAllStackTraces((Map) result));
                }
            }
        });

        hookMethods(StackTraceElement.class, "getClassName", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (active && result instanceof String && containsHiddenToken((String) result)) {
                    param.setResult("java.lang.reflect.Method");
                }
            }
        });
    }

    private static void installLibXloaderReportHook(final ClassLoader appClassLoader) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> reportClass = Class.forName("fiqlohqeo.aH", false, appClassLoader);

                Method readReport = reportClass.getDeclaredMethod("a");
                readReport.setAccessible(true);
                XposedBridge.hookMethod(readReport, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (result instanceof String && shouldSuppressReport((String) result)) {
                            XposedBridge.log(TAG + "native report read " + safeLogValue((String) result));
                        }
                    }
                });

                Method exitReport = reportClass.getDeclaredMethod("a", String.class);
                exitReport.setAccessible(true);
                XposedBridge.hookMethod(exitReport, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String report = stringArg(param, 0);
                        if (shouldSuppressReport(report)) {
                            XposedBridge.log(TAG + "suppress native report " + safeLogValue(report));
                            param.setResult(null);
                        }
                    }
                });
            }
        });
    }

    private static void hookMethods(final Class<?> type, final String name, final XC_MethodHook hook) {
        hookMatchingMethods(type, name, null, hook);
    }

    private static void hookMatchingMethods(final Class<?> type, final String name, final MethodMatcher matcher, final XC_MethodHook hook) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() {
                Method[] methods = type.getDeclaredMethods();
                for (int i = 0; i < methods.length; i++) {
                    Method method = methods[i];
                    if (!name.equals(method.getName())) {
                        continue;
                    }
                    if (matcher != null && !matcher.matches(method)) {
                        continue;
                    }
                    method.setAccessible(true);
                    XposedBridge.hookMethod(method, hook);
                }
            }
        });
    }

    private static boolean shouldHideLookup(String name) {
        return active && !isInternal() && containsHiddenToken(name);
    }

    private static void resolveClassForNameWithAppLoader(XC_MethodHook.MethodHookParam param, String name, ClassLoader appClassLoader) {
        Boolean previous = INTERNAL.get();
        INTERNAL.set(Boolean.TRUE);
        try {
            param.setResult(Class.forName(name, true, appClassLoader));
        } catch (ClassNotFoundException ignored) {
            // Let the original call fail so optional-class probes do not expose this module in the exception stack.
        } catch (Throwable throwable) {
            param.setThrowable(sanitizeThrowable(throwable));
        } finally {
            if (previous == null) {
                INTERNAL.remove();
            } else {
                INTERNAL.set(previous);
            }
        }
    }

    private static void logHidden(String source, String value) {
        synchronized (JavaHideModule.class) {
            if (hiddenLogCount >= 64) {
                return;
            }
            hiddenLogCount++;
        }
        XposedBridge.log(TAG + "hide " + source + " " + value);
    }

    private static Throwable sanitizeThrowable(Throwable throwable) {
        if (throwable != null && throwable.getStackTrace() != null) {
            throwable.setStackTrace(filterStackTrace(throwable.getStackTrace()));
        }
        return throwable;
    }

    private static String stringArg(XC_MethodHook.MethodHookParam param, int index) {
        if (param == null || param.args == null || param.args.length <= index || !(param.args[index] instanceof String)) {
            return null;
        }
        return (String) param.args[index];
    }

    private static boolean isIntentOrIntentArray(Class<?> type) {
        if (type == null) {
            return false;
        }
        if ("android.content.Intent".equals(type.getName())) {
            return true;
        }
        return type.isArray()
                && type.getComponentType() != null
                && "android.content.Intent".equals(type.getComponentType().getName());
    }

    private static boolean shouldBlockIntentObject(Object value) {
        if (value == null) {
            return false;
        }
        Class<?> type = value.getClass();
        if (type.isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (shouldBlockIntentObject(Array.get(value, i))) {
                    return true;
                }
            }
            return false;
        }
        if (!"android.content.Intent".equals(type.getName())) {
            return false;
        }

        String action = invokeString(value, "getAction");
        String data = invokeString(value, "getDataString");
        return "android.intent.action.VIEW".equals(action)
                && data != null
                && data.toLowerCase().indexOf("bochk.com") >= 0;
    }

    private static String invokeString(Object target, String methodName) {
        Object value = invokeNoArg(target, methodName);
        return value == null ? null : String.valueOf(value);
    }

    private static StackTraceElement[] filterStackTrace(StackTraceElement[] stack) {
        if (stack == null || stack.length == 0) {
            return stack;
        }

        StackTraceElement[] tmp = new StackTraceElement[stack.length];
        int count = 0;
        for (int i = 0; i < stack.length; i++) {
            StackTraceElement element = stack[i];
            if (!isHiddenStackElement(element)) {
                tmp[count++] = element;
            }
        }
        if (count == stack.length) {
            return stack;
        }

        StackTraceElement[] filtered = new StackTraceElement[count];
        System.arraycopy(tmp, 0, filtered, 0, count);
        return filtered;
    }

    private static Map filterAllStackTraces(Map traces) {
        if (traces == null || traces.isEmpty()) {
            return traces;
        }

        HashMap filtered = new HashMap();
        boolean changed = false;
        for (Object entryObject : traces.entrySet()) {
            Map.Entry entry = (Map.Entry) entryObject;
            Object key = entry.getKey();
            Object value = entry.getValue();
            if (key instanceof Thread && containsHiddenToken(((Thread) key).getName())) {
                changed = true;
                continue;
            }
            if (value instanceof StackTraceElement[]) {
                StackTraceElement[] stack = (StackTraceElement[]) value;
                StackTraceElement[] cleanStack = filterStackTrace(stack);
                changed = changed || cleanStack != stack;
                filtered.put(key, cleanStack);
            } else {
                filtered.put(key, value);
            }
        }

        return changed ? filtered : traces;
    }

    private static boolean isHiddenStackElement(StackTraceElement element) {
        if (element == null) {
            return false;
        }
        return containsHiddenToken(element.getClassName())
                || containsHiddenToken(element.getFileName())
                || containsHiddenToken(element.getMethodName());
    }

    private static boolean shouldSanitizeFieldResult(Field field, Object result) {
        if (field == null || result == null) {
            return false;
        }
        String declaringClass = field.getDeclaringClass() == null ? null : field.getDeclaringClass().getName();
        if (declaringClass == null || declaringClass.indexOf("dalvik.system.") != 0) {
            return false;
        }
        return objectContainsHiddenToken(result);
    }

    private static Object sanitizeFieldResult(Object result, String appSourceDir) {
        if (result == null) {
            return null;
        }
        if (result instanceof String) {
            return containsHiddenToken((String) result) ? replacementPath(appSourceDir) : result;
        }
        if (result instanceof File) {
            return containsHiddenToken(((File) result).getPath()) ? new File(replacementPath(appSourceDir)) : result;
        }
        Class<?> resultClass = result.getClass();
        if (!resultClass.isArray()) {
            return result;
        }

        int length = Array.getLength(result);
        Object[] tmp = new Object[length];
        int count = 0;
        boolean changed = false;
        for (int i = 0; i < length; i++) {
            Object item = Array.get(result, i);
            if (objectContainsHiddenToken(item)) {
                changed = true;
                continue;
            }
            tmp[count++] = item;
        }
        if (!changed) {
            return result;
        }

        Object filtered = Array.newInstance(resultClass.getComponentType(), count);
        for (int i = 0; i < count; i++) {
            Array.set(filtered, i, tmp[i]);
        }
        return filtered;
    }

    private static boolean objectContainsHiddenToken(Object value) {
        if (value == null) {
            return false;
        }
        if (value instanceof String) {
            return containsHiddenToken((String) value);
        }
        if (value instanceof File) {
            return containsHiddenToken(((File) value).getPath());
        }
        Class<?> valueClass = value.getClass();
        if (containsHiddenToken(valueClass.getName())) {
            return true;
        }
        if (valueClass.isArray()) {
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                if (objectContainsHiddenToken(Array.get(value, i))) {
                    return true;
                }
            }
            return false;
        }
        if (valueClass.getName().indexOf("dalvik.system.") != 0) {
            return containsHiddenToken(String.valueOf(value));
        }
        return dalvikObjectContainsHiddenToken(value);
    }

    private static boolean dalvikObjectContainsHiddenToken(Object value) {
        Boolean previous = INTERNAL.get();
        INTERNAL.set(Boolean.TRUE);
        try {
            Field[] fields = value.getClass().getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                Field field = fields[i];
                String name = field.getName();
                if (!isDexPathFieldName(name)) {
                    continue;
                }
                field.setAccessible(true);
                Object fieldValue = field.get(value);
                if (objectContainsHiddenToken(fieldValue)) {
                    return true;
                }
            }
        } catch (Throwable ignored) {
        } finally {
            if (previous == null) {
                INTERNAL.remove();
            } else {
                INTERNAL.set(previous);
            }
        }
        return containsHiddenToken(String.valueOf(value));
    }

    private static boolean isDexPathFieldName(String name) {
        return "path".equals(name)
                || "pathList".equals(name)
                || "dexElements".equals(name)
                || "dexFile".equals(name)
                || "file".equals(name)
                || "zip".equals(name)
                || "zipFile".equals(name)
                || "nativeLibraryPathElements".equals(name)
                || "nativeLibraryDirectories".equals(name);
    }

    private static boolean classLoaderLooksInjected(ClassLoader classLoader) {
        if (classLoader == null || classLoader == cleanAppClassLoader) {
            return false;
        }
        String className = classLoader.getClass().getName();
        if (!"java.lang.BootClassLoader".equals(className)) {
            return true;
        }
        return containsHiddenToken(className);
    }

    private static boolean isTargetAppClassName(String className) {
        return className != null
                && (className.indexOf("fiqlohqeo.") == 0
                || className.indexOf("com.bochk.") == 0);
    }

    private static Object invokeNoArg(Object target, String methodName) {
        if (target == null || methodName == null) {
            return null;
        }
        try {
            Method method = target.getClass().getMethod(methodName);
            method.setAccessible(true);
            return method.invoke(target);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String stringField(Object target, String name) {
        Object value = fieldValue(target, name);
        return value instanceof String ? (String) value : null;
    }

    private static Object fieldValue(Object target, String name) {
        Field field = findField(target == null ? null : target.getClass(), name);
        if (field == null) {
            return null;
        }
        try {
            field.setAccessible(true);
            return field.get(target);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean setFieldValue(Object target, String name, Object value) {
        Field field = findField(target == null ? null : target.getClass(), name);
        if (field == null) {
            return false;
        }
        try {
            field.setAccessible(true);
            field.set(target, value);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static Field findField(Class<?> type, String name) {
        Class<?> cursor = type;
        while (cursor != null && name != null) {
            try {
                return cursor.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                cursor = cursor.getSuperclass();
            } catch (Throwable ignored) {
                return null;
            }
        }
        return null;
    }

    private static String sanitizedClassLoaderString(Object classLoader, String appSourceDir) {
        String className = classLoader == null ? "dalvik.system.PathClassLoader" : classLoader.getClass().getName();
        return className + "[DexPathList[[" + replacementPath(appSourceDir) + "]]]";
    }

    private static String replacementPath(String appSourceDir) {
        if (cleanAppSourceDir != null) {
            return cleanAppSourceDir;
        }
        return appSourceDir == null ? "/system/framework/framework.jar" : appSourceDir;
    }

    private static boolean containsHiddenToken(String value) {
        if (value == null) {
            return false;
        }
        String lower = value.toLowerCase();
        for (int i = 0; i < HIDDEN_TOKENS.length; i++) {
            if (lower.indexOf(HIDDEN_TOKENS[i]) >= 0) {
                return true;
            }
        }
        return false;
    }

    private static boolean startsWithReportCode(String value, String code) {
        return value != null && value.startsWith(code);
    }

    private static boolean shouldSuppressReport(String value) {
        return startsWithReportCode(value, "16") || startsWithReportCode(value, "03");
    }

    private static String safeLogValue(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= 96) {
            return value;
        }
        return value.substring(0, 96) + "...";
    }

    private static boolean isTargetPackage(String packageName) {
        for (int i = 0; i < TARGET_PACKAGES.length; i++) {
            if (TARGET_PACKAGES[i].equals(packageName)) {
                return true;
            }
        }
        return false;
    }

    private static void runInternal(ThrowingRunnable runnable) {
        Boolean previous = INTERNAL.get();
        INTERNAL.set(Boolean.TRUE);
        try {
            runnable.run();
        } catch (Throwable throwable) {
            XposedBridge.log(throwable);
        } finally {
            if (previous == null) {
                INTERNAL.remove();
            } else {
                INTERNAL.set(previous);
            }
        }
    }

    private static boolean isInternal() {
        return Boolean.TRUE.equals(INTERNAL.get());
    }

    private interface ThrowingRunnable {
        void run() throws Throwable;
    }

    private interface MethodMatcher {
        boolean matches(Method method);
    }
}
