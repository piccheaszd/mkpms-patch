#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
CLASSES="$BUILD/classes"
STUB_CLASSES="$BUILD/stub-classes"
STUB_JAR="$BUILD/xposed-stubs.jar"
UNSIGNED="$BUILD/java-hide-lsposed.unsigned.apk"
ALIGNED="$BUILD/java-hide-lsposed.aligned.apk"
APK="$BUILD/java-hide-lsposed.apk"
KEYSTORE="$BUILD/debug.keystore"
FRAMEWORK_RES="${FRAMEWORK_RES:-/usr/share/android-framework-res/framework-res.apk}"
R8_VERSION="${R8_VERSION:-9.1.31}"
R8_JAR="${R8_JAR:-$BUILD/r8-$R8_VERSION.jar}"

rm -rf "$CLASSES" "$STUB_CLASSES"
mkdir -p "$CLASSES" "$STUB_CLASSES"

javac --release 8 -d "$STUB_CLASSES" $(find "$ROOT/stubs" -name '*.java' | sort)
jar cf "$STUB_JAR" -C "$STUB_CLASSES" .

javac --release 8 -cp "$STUB_JAR" -d "$CLASSES" $(find "$ROOT/src/main/java" -name '*.java' | sort)
jar cf "$BUILD/program.jar" -C "$CLASSES" .
if [[ ! -f "$R8_JAR" ]]; then
    curl -fL --retry 3 \
        -o "$R8_JAR" \
        "https://dl.google.com/dl/android/maven2/com/android/tools/r8/$R8_VERSION/r8-$R8_VERSION.jar"
fi
rm -rf "$BUILD/dex"
mkdir -p "$BUILD/dex"
java -cp "$R8_JAR" com.android.tools.r8.D8 \
    --min-api 26 \
    --output "$BUILD/dex" \
    "$BUILD/program.jar"
cp "$BUILD/dex/classes.dex" "$BUILD/classes.dex"

aapt package -f \
    -M "$ROOT/AndroidManifest.xml" \
    -I "$FRAMEWORK_RES" \
    -S "$ROOT/src/main/res" \
    -A "$ROOT/src/main/assets" \
    -F "$UNSIGNED" >/dev/null

zip -j "$UNSIGNED" "$BUILD/classes.dex" >/dev/null
zipalign -f -p 4 "$UNSIGNED" "$ALIGNED"

if [[ ! -f "$KEYSTORE" ]]; then
    keytool -genkeypair \
        -keystore "$KEYSTORE" \
        -storepass android \
        -keypass android \
        -alias androiddebugkey \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$APK" \
    "$ALIGNED"

apksigner verify "$APK"
echo "$APK"
