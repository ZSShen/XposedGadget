package org.zsshen.signaturehunter;


import android.content.pm.PackageInfo;
import android.content.pm.Signature;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;


public class SignatureHunter implements IXposedHookLoadPackage {
    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam pkgParam) throws Throwable {
        if (!pkgParam.packageName.equals("com.zwodrxcj.xnynjps"))
            return;
        XposedBridge.log("Capture App: " + pkgParam.packageName);

        XposedHelpers.findAndHookMethod("android.app.ApplicationPackageManager",
                pkgParam.classLoader, "getPackageInfo", String.class, int.class, new XC_MethodHook() {
                    protected void afterHookedMethod(MethodHookParam methodParam) throws Throwable {

                        PackageInfo pkgInfo =
                                (PackageInfo) methodParam.getResult();
                        Signature[] signatures = pkgInfo.signatures;
                        StringBuilder sb = new StringBuilder();
                        for (Signature signature : signatures) {
                            sb.append(convertByteArrayToString(signature.toByteArray()));
                            sb.append("\n");
                        }
                        int len = sb.length();
                        sb.deleteCharAt(len - 1);
                        String payload = sb.toString();
                        XposedBridge.log("Package Signatures: " + payload);

                        sb = new StringBuilder();
                        sb.append("sdcard");
                        sb.append(File.separator);
                        sb.append("signatures.db");

                        File dump = new File(sb.toString());
                        if (dump.exists()) {
                            BufferedReader reader =
                                    new BufferedReader(new InputStreamReader(new FileInputStream(dump)));
                            payload = reader.readLine();
                            String[] split = payload.split("\n");
                            int idx = 0;
                            for (String signature : split) {
                                signatures[idx] =
                                        new Signature(convertStringToByteArray(signature));
                                ++idx;
                            }
                        } else {
                            dump.createNewFile();
                            BufferedWriter writer =
                                    new BufferedWriter(new OutputStreamWriter(new FileOutputStream(dump)));
                            writer.write(payload);
                            writer.close();
                        }
                    }
                });
    }

    public String convertByteArrayToString(byte[] array) {
        StringBuilder sb = new StringBuilder();
        for (byte ch : array) {
            sb.append(ch);
            sb.append(',');
        }
        int len = sb.length();
        sb.deleteCharAt(len - 1);
        return sb.toString();
    }

    public byte[] convertStringToByteArray(String string) {
        String[] split = string.split(",");
        byte[] array = new byte[split.length];
        int idx = 0;
        for (String num : split) {
            byte ch = Byte.valueOf(num);
            array[idx++] = ch;
        }
        return array;
    }
}
