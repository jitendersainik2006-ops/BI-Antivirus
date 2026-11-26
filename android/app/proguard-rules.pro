# BI Antivirus Enterprise - Proguard / R8 Optimization Rules
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# Keep serializable threat models
-keepclassmembers class com.biantivirus.security.model.** { *; }
-keepclassmembers enum com.biantivirus.security.model.** { *; }

# Keep AndroidX Security Crypto primitives
-keepclassmembers class androidx.security.crypto.** { *; }
