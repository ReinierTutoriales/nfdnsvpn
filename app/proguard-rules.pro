# JNI methods of NativeCore are kept by the default rules (native <methods>).
# Called from native code (the tunnel's owner lookup), so R8 sees no caller.
-keep class com.reiniertutoriales.nfdnsvpn.core.ConnectionOwner {
    public static int find(int, byte[], int, byte[], int);
}
