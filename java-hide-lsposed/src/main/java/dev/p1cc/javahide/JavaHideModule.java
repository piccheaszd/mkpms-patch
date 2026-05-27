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
    private static final String PACKAGE_BOCHK = "com.bochk.app.aos";
    private static final String PACKAGE_OPLUS_SECURITY_PERMISSION = "com.oplus.securitypermission";

    private static final String[] TARGET_PACKAGES = {
            PACKAGE_BOCHK,
            PACKAGE_OPLUS_SECURITY_PERMISSION
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
            "zygisk",
            "javahide",
            "dev.p1cc.javahide"
    };

    private static final ThreadLocal<Boolean> INTERNAL = new ThreadLocal<Boolean>();
    private static volatile boolean active;
    private static volatile ClassLoader cleanAppClassLoader;
    private static volatile String cleanAppSourceDir;
    private static volatile String cleanNativeLibraryDir;
    private static volatile boolean bochkIntegrityGateHookInstalled;
    private static int hiddenLogCount;

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || !isTargetPackage(lpparam.packageName)) {
            return;
        }

        if (PACKAGE_OPLUS_SECURITY_PERMISSION.equals(lpparam.packageName)) {
            installOplusStartConfirmHook(lpparam.classLoader);
            XposedBridge.log(TAG + "installed OPlus start-confirm blocker for " + lpparam.processName);
            return;
        }

        if (PACKAGE_BOCHK.equals(lpparam.packageName)) {
            if (PACKAGE_BOCHK.equals(lpparam.processName)) {
                installBochkReportHook(lpparam.classLoader);
                XposedBridge.log(TAG + "installed BOCHK report blocker for " + lpparam.processName);
            } else {
                XposedBridge.log(TAG + "skip BOCHK helper process " + lpparam.processName);
            }
            return;
        }

        active = false;
        cleanAppClassLoader = null;
        cleanAppSourceDir = null;
        cleanNativeLibraryDir = null;
        bochkIntegrityGateHookInstalled = false;
        prepareCleanClassLoader(fieldValue(lpparam, "appInfo"), lpparam.classLoader);
        installClassLoaderSurfaceHooks(cleanAppSourceDir);
        installContextClassLoaderHooks();
        installIntentHooks();
        installActivationHook();
        XposedBridge.log(TAG + "installed for " + lpparam.packageName + " / " + lpparam.processName);
    }

    private static void installOplusStartConfirmHook(final ClassLoader classLoader) {
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> activityClass = Class.forName(
                        "com.oplusos.securitypermission.permission.ui.AppStartConfirmDialogActivity",
                        false,
                        classLoader);
                Class<?> appStartDataClass = Class.forName(
                        "com.oplusos.securitypermission.permission.ui.AppStartConfirmDialogActivity$a",
                        false,
                        classLoader);

                hookMatchingMethods(activityClass, "E", new MethodMatcher() {
                    @Override
                    public boolean matches(Method method) {
                        Class<?>[] parameterTypes = method.getParameterTypes();
                        return parameterTypes.length == 1 && parameterTypes[0] == appStartDataClass;
                    }
                }, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Object appStartData = param.args == null || param.args.length == 0 ? null : param.args[0];
                        if (!shouldBlockOplusAppStartData(appStartData)) {
                            return;
                        }
                        XposedBridge.log(TAG + "suppress OPlus startActivityAsCaller " + safeLogValue(String.valueOf(appStartData)));
                        param.setResult(null);
                    }
                });

                hookMatchingMethods(activityClass, "D", new MethodMatcher() {
                    @Override
                    public boolean matches(Method method) {
                        Class<?>[] parameterTypes = method.getParameterTypes();
                        return parameterTypes.length == 2 && parameterTypes[0] == appStartDataClass;
                    }
                }, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        Object appStartData = param.args == null || param.args.length == 0 ? null : param.args[0];
                        if (!shouldBlockOplusAppStartData(appStartData)) {
                            return;
                        }
                        XposedBridge.log(TAG + "auto-close OPlus start confirm " + safeLogValue(String.valueOf(appStartData)));
                        invokeOplusStartConfirmDecision(param.thisObject, appStartData, -1, false);
                        param.setResult(null);
                    }
                });
            }
        });
    }

    private static boolean shouldBlockOplusAppStartData(Object appStartData) {
        if (appStartData == null) {
            return false;
        }

        String caller = invokeString(appStartData, "d");
        if (!PACKAGE_BOCHK.equals(caller)) {
            return false;
        }

        Object sourceIntent = invokeNoArg(appStartData, "e");
        if (shouldBlockIntentObject(sourceIntent)) {
            return true;
        }

        String callee = invokeString(appStartData, "b");
        String value = String.valueOf(appStartData).toLowerCase();
        return callee != null
                && value.indexOf("bochk.com") >= 0
                && (callee.indexOf("browser") >= 0 || callee.indexOf("firefox") >= 0 || callee.indexOf("chrome") >= 0);
    }

    private static void invokeOplusStartConfirmDecision(Object activity, Object appStartData, int which, boolean checked) {
        if (activity == null || appStartData == null) {
            return;
        }
        try {
            Method decision = activity.getClass().getDeclaredMethod("B", Integer.TYPE, Boolean.TYPE, appStartData.getClass());
            decision.setAccessible(true);
            decision.invoke(activity, Integer.valueOf(which), Boolean.valueOf(checked), appStartData);
        } catch (Throwable throwable) {
            XposedBridge.log(TAG + "failed to auto-close OPlus start confirm: " + throwable);
        }
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

    private static void prepareCleanClassLoader(final Object appInfo, final ClassLoader fallbackClassLoader) {
        if (cleanAppClassLoader != null) {
            return;
        }
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                String sourceDir = stringField(appInfo, "sourceDir");
                String nativeLibraryDir = stringField(appInfo, "nativeLibraryDir");
                String dexPath = sourceDir;
                if (dexPath == null || dexPath.length() == 0) {
                    dexPath = extractApkDexPath(fallbackClassLoader);
                    sourceDir = firstPathEntry(dexPath);
                }
                if (dexPath == null || dexPath.length() == 0 || sourceDir == null || sourceDir.length() == 0) {
                    return;
                }

                Class<?> pathClassLoaderClass = Class.forName("dalvik.system.PathClassLoader");
                Object clean = pathClassLoaderClass
                        .getConstructor(String.class, String.class, ClassLoader.class)
                        .newInstance(dexPath, nativeLibraryDir, ClassLoader.getSystemClassLoader().getParent());
                if (!(clean instanceof ClassLoader)) {
                    return;
                }

                cleanAppSourceDir = sourceDir;
                cleanNativeLibraryDir = nativeLibraryDir;
                cleanAppClassLoader = (ClassLoader) clean;
                Thread.currentThread().setContextClassLoader(cleanAppClassLoader);
                XposedBridge.log(TAG + "clean classloader prepared source=" + sourceDir);
            }
        });
    }

    private static String extractApkDexPath(Object classLoader) {
        String value = String.valueOf(classLoader);
        StringBuilder dexPath = new StringBuilder();
        int search = 0;
        while (value != null) {
            int start = value.indexOf("/data/app/", search);
            if (start < 0) {
                start = value.indexOf("/mnt/expand/", search);
            }
            if (start < 0) {
                break;
            }
            int end = value.indexOf(".apk", start);
            if (end < 0) {
                break;
            }
            end += 4;
            String path = value.substring(start, end);
            if (dexPath.indexOf(path) < 0) {
                if (dexPath.length() > 0) {
                    dexPath.append(File.pathSeparator);
                }
                dexPath.append(path);
            }
            search = end;
        }
        return dexPath.length() == 0 ? null : dexPath.toString();
    }

    private static String firstPathEntry(String path) {
        if (path == null || path.length() == 0) {
            return null;
        }
        int separator = path.indexOf(File.pathSeparator);
        return separator < 0 ? path : path.substring(0, separator);
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

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                maybeInstallBochkIntegrityGateHook(param.getResult());
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
                hookMethods(dexFile, "toString", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) {
                        Object result = param.getResult();
                        if (active && result instanceof String && containsHiddenToken((String) result)) {
                            logHidden("DexFile.toString", (String) result);
                            param.setResult("DexFile[" + replacementPath(appSourceDir) + "]");
                        }
                    }
                });
                hookDexFileClassLoaderContextMethods(dexFile, appSourceDir);
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

    private static void hookDexFileClassLoaderContextMethods(final Class<?> dexFile, final String appSourceDir) {
        hookMatchingMethods(dexFile, "getClassLoaderContext", new MethodMatcher() {
            @Override
            public boolean matches(Method method) {
                return method.getReturnType() == String.class;
            }
        }, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (!active || !(result instanceof String)) {
                    return;
                }
                String context = (String) result;
                if (containsHiddenToken(context) || context.toLowerCase().indexOf("unsupported") >= 0) {
                    logHidden("DexFile.getClassLoaderContext", context);
                    param.setResult(sanitizedClassLoaderContext(appSourceDir));
                }
            }
        });

        hookMatchingMethods(dexFile, "isValidClassLoaderContext", new MethodMatcher() {
            @Override
            public boolean matches(Method method) {
                return method.getReturnType() == Boolean.TYPE;
            }
        }, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) {
                if (!active || !argsContainClassLoaderArtifact(param)) {
                    return;
                }
                logHidden("DexFile.isValidClassLoaderContext", argsToString(param));
                param.setResult(Boolean.TRUE);
            }
        });

        hookDexFileStringOutputMethod(dexFile, "getDexFileOutputPath", appSourceDir);
        hookDexFileStringOutputMethod(dexFile, "getDexFileStatus", appSourceDir);
    }

    private static void hookDexFileStringOutputMethod(final Class<?> dexFile, final String methodName, final String appSourceDir) {
        hookMatchingMethods(dexFile, methodName, new MethodMatcher() {
            @Override
            public boolean matches(Method method) {
                return method.getReturnType() == String.class;
            }
        }, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                Object result = param.getResult();
                if (active && result instanceof String && containsHiddenToken((String) result)) {
                    logHidden("DexFile." + methodName, (String) result);
                    param.setResult(replacementPath(appSourceDir));
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

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                maybeInstallBochkIntegrityGateHook(param.getResult());
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

            @Override
            protected void afterHookedMethod(MethodHookParam param) {
                maybeInstallBochkIntegrityGateHook(param.getResult());
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

    private static void installBochkReportHook(final ClassLoader appClassLoader) {
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
                            XposedBridge.log(TAG + "suppress native report read " + safeLogValue((String) result));
                            param.setResult("");
                        }
                    }
                });

                Method startReportThread = reportClass.getDeclaredMethod("c");
                startReportThread.setAccessible(true);
                XposedBridge.hookMethod(startReportThread, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        XposedBridge.log(TAG + "suppress native report thread");
                        param.setResult(null);
                    }
                });

                Method exitReport = reportClass.getDeclaredMethod("a", String.class);
                exitReport.setAccessible(true);
                XposedBridge.hookMethod(exitReport, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) {
                        String report = stringArg(param, 0);
                        XposedBridge.log(TAG + "suppress native report dispatch " + safeLogValue(report));
                        param.setResult(null);
                    }
                });
            }
        });
    }

    private static void installBochkIntegrityGateHook(final ClassLoader appClassLoader) {
        if (bochkIntegrityGateHookInstalled || appClassLoader == null) {
            return;
        }
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                Class<?> loaderClass = Class.forName("fiqlohqeo.ap", false, appClassLoader);
                installBochkIntegrityGateHook(loaderClass);
            }
        });
    }

    private static void maybeInstallBochkIntegrityGateHook(Object value) {
        if (bochkIntegrityGateHookInstalled || !(value instanceof Class)) {
            return;
        }
        Class<?> type = (Class<?>) value;
        if ("fiqlohqeo.ap".equals(type.getName())) {
            installBochkIntegrityGateHook(type);
        }
    }

    private static void installBochkIntegrityGateHook(final Class<?> loaderClass) {
        if (loaderClass == null || !"fiqlohqeo.ap".equals(loaderClass.getName())) {
            return;
        }
        runInternal(new ThrowingRunnable() {
            @Override
            public void run() throws Throwable {
                synchronized (JavaHideModule.class) {
                    if (bochkIntegrityGateHookInstalled) {
                        return;
                    }
                    Method integrityGate = loaderClass.getDeclaredMethod("d");
                    integrityGate.setAccessible(true);
                    XposedBridge.hookMethod(integrityGate, new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            XposedBridge.log(TAG + "force BOCHK integrity gate false");
                            param.setResult(Boolean.FALSE);
                        }
                    });
                    bochkIntegrityGateHookInstalled = true;
                    XposedBridge.log(TAG + "BOCHK integrity gate hook installed");
                }
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
        if (containsHiddenToken(className)) {
            return true;
        }
        if ("java.lang.BootClassLoader".equals(className)) {
            return false;
        }
        return dalvikObjectContainsHiddenToken(classLoader);
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

    private static String sanitizedClassLoaderContext(String appSourceDir) {
        return "PCL[" + replacementPath(appSourceDir) + "]";
    }

    private static boolean argsContainClassLoaderArtifact(XC_MethodHook.MethodHookParam param) {
        if (param == null || param.args == null) {
            return false;
        }
        for (int i = 0; i < param.args.length; i++) {
            Object arg = param.args[i];
            if (!(arg instanceof String)) {
                continue;
            }
            String value = (String) arg;
            if (containsHiddenToken(value) || value.toLowerCase().indexOf("unsupported") >= 0) {
                return true;
            }
        }
        return false;
    }

    private static String argsToString(XC_MethodHook.MethodHookParam param) {
        if (param == null || param.args == null || param.args.length == 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < param.args.length; i++) {
            if (i > 0) {
                builder.append(", ");
            }
            builder.append(String.valueOf(param.args[i]));
        }
        return safeLogValue(builder.toString());
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
        return startsWithReportCode(value, "16")
                || startsWithReportCode(value, "03")
                || startsWithReportCode(value, "00");
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
