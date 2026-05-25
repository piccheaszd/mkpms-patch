package de.robv.android.xposed;

public abstract class XC_MethodHook {
    public static final class MethodHookParam {
        public Object thisObject;
        public Object[] args;

        public Object getResult() {
            return null;
        }

        public void setResult(Object result) {
        }

        public void setThrowable(Throwable throwable) {
        }
    }

    public static class Unhook {
    }

    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
    }

    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
    }
}
