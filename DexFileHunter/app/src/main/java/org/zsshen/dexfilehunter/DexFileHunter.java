package org.zsshen.dexfilehunter;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.Enumeration;

import dalvik.system.DexFile;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class DexFileHunter implements IXposedHookLoadPackage {
    static {
        System.loadLibrary("EggHunt");
    }

    public native void ScanMemory();

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam pkgParam) throws Throwable {
        if (!pkgParam.packageName.equals("tx.qq898507339.bzy9"))
            return;
        XposedBridge.log("Capture App: " + pkgParam.packageName);

        XposedHelpers.findAndHookMethod("dalvik.system.DexFile",
                pkgParam.classLoader, "loadDex",
                String.class, String.class, int.class, new XC_MethodHook() {
                    protected void beforeHookedMethod(MethodHookParam methodParam) throws Throwable {
                        String pathSrc = (String) methodParam.args[0];
                        String pathDst = (String) methodParam.args[1];
                        XposedBridge.log("\tSource Path: " + pathSrc);
                        XposedBridge.log("\tTarget Path: " + pathDst);
                    }

                    protected void afterHookedMethod(MethodHookParam methodParam) throws Throwable {
                        DexFile dexFile = (DexFile) methodParam.getResult();
                        XposedBridge.log("Capture Dex File: " + dexFile.toString());

                        Enumeration<String> entries = dexFile.entries();
                        while (entries.hasMoreElements()) {
                            String clazzName = entries.nextElement();
                            if (clazzName.startsWith("android.support"))
                                continue;
                            XposedBridge.log("\tCapture class: " + clazzName);
                        }

                        ScanMemory();
                    }
                });
    }
}
