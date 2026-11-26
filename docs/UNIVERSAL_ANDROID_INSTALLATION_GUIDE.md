# BI Antivirus Enterprise — Universal Android Installation Guide
### Black Intel Cyber Defense Platform — Mobile Endpoint Security (v1.1.0)
**Universal Compatibility:** Samsung &bull; Google Pixel &bull; OnePlus &bull; Xiaomi / Redmi / POCO &bull; vivo / iQOO &bull; OPPO / realme &bull; Motorola &bull; Nothing &bull; Generic Android (API 26–34+)

---

## Language Selection / भाषा चयन
- [English Installation Guide](#english-installation-guide)
- [हिंदी इंस्टॉलेशन निर्देश (Hindi Guide)](#हिंदी-इंस्टॉलेशन-निर्देश-hindi-installation-guide)
- [Manufacturer Battery Optimization Settings](#manufacturer-battery-optimization-settings)

---

# English Installation Guide

You can install **BI Antivirus Enterprise v1.1.0** on your Android device using any of the following three methods:

### Method 1: Automated 1-Click USB Assistant (Recommended for PC Users)
*Requires a USB data cable and a Windows laptop/PC.*

1. **Connect your phone:** Plug your phone into your PC using a USB data cable.
2. **Enable USB File Transfer:** On your phone screen, swipe down the notification bar, tap **Charging via USB**, and select **File Transfer / Android Auto**.
3. **Enable USB Debugging:**
   - Go to **Settings > About Phone**.
   - Tap **Build Number** 7 times until you see the message *"You are now a developer!"*.
   - Go to **Settings > System > Developer options** (or **Additional settings > Developer options** on Xiaomi/vivo/OPPO).
   - Toggle **USB Debugging** to **ON**.
4. **Run the Installer:**
   - On your PC, navigate to `D:\bit defender\`.
   - Double-click **`INSTALL_BI_ANTIVIRUS.bat`**.
5. **Approve Authorization Prompt:**
   - Look at your phone screen. When prompted *"Allow USB debugging?"*, check the box **"Always allow from this computer"** and tap **Allow**.
6. **Confirm Installation:** Press `Y` in the command window. The APK will be transferred and installed non-destructively (preserving all user settings).

---

### Method 2: Wireless Local Wi-Fi QR Code Transfer (No Cable Required)
*Requires phone and PC to be connected to the same Wi-Fi network.*

1. **Start the Local Server:**
   - On your PC, double-click **`START_QR_INSTALLATION.bat`** in `D:\bit defender\`.
2. **Scan the QR Code:**
   - Open your phone's Camera (or Google Lens).
   - Point your camera at the QR code displayed in the command prompt or open `D:\bit defender\build\staging_android\download_qr_code.png`.
   - Tap the link that appears on your phone screen (`http://<PC_IP>:8765/download?token=...`).
3. **Download & Install:**
   - Tap **"Download Official APK"** on the webpage.
   - Once downloaded, tap the notification or open your **Files / Downloads** folder.
   - Tap **BI_Antivirus_Enterprise_v1.1.0.apk**.
   - If prompted *"For your security, your phone is not allowed to install unknown apps from this source"*, tap **Settings**, toggle **Allow from this source** to **ON**, and tap **Install**.

---

### Method 3: Manual Direct File Transfer
*For users who prefer standard file transfer without tools.*

1. **Locate the APK:**
   - On your PC, find the file at:
     `D:\bit defender\build\staging_android\BI_Antivirus_Enterprise_v1.1.0.apk`
2. **Transfer to Phone:**
   - Connect phone via USB cable and drag the file into your phone's **Download** or **Documents** folder.
   - *(Alternative)* Send it to yourself via Bluetooth, Google Drive, WhatsApp, or Telegram.
3. **Install on Phone:**
   - Open the **Files** or **File Manager** app on your phone.
   - Go to **Downloads** and tap `BI_Antivirus_Enterprise_v1.1.0.apk`.
   - Tap **Install**. If prompted, grant permission to install from your file manager.
4. **Launch:** Tap **Open** or launch **BI Antivirus** from your home screen.

---

# हिंदी इंस्टॉलेशन निर्देश (Hindi Installation Guide)

आप अपने एंड्रॉइड फ़ोन या टैबलेट पर **BI Antivirus Enterprise v1.1.0** को निम्नलिखित तीन तरीकों में से किसी एक से आसानी से इंस्टॉल कर सकते हैं:

### तरीका 1: ऑटोमैटिक 1-क्लिक USB इंस्टॉलर (कंप्यूटर यूज़र्स के लिए)
*इसके लिए USB डेटा केबल और विंडोज लैपटॉप/पीसी की आवश्यकता है।*

1. **फ़ोन को कनेक्ट करें:** अपने फ़ोन को USB डेटा केबल के ज़रिए लैपटॉप से जोड़ें।
2. **फ़ाइल ट्रांसफर चुनें:** फ़ोन की स्क्रीन पर ऊपर से नीचे स्वाइप करें, USB नोटिफिकेशन पर टैप करें और **'File Transfer' (फ़ाइल ट्रांसफर)** चुनें।
3. **USB डीबगिंग चालू करें:**
   - फ़ोन की **Settings (सेटिंग्स) > About Phone (फ़ोन के बारे में)** में जाएं।
   - **Build Number (बिल्ड नंबर)** पर लगातार 7 बार टैप करें जब तक लिखा न आए *"You are now a developer"*.
   - अब **Settings > System > Developer options** (डेवलपर विकल्प) में जाएं।
   - **USB Debugging** को चालू (**ON**) करें।
4. **इंस्टॉलर चलाएं:**
   - अपने कंप्यूटर पर `D:\bit defender\` फ़ोल्डर खोलें।
   - **`INSTALL_BI_ANTIVIRUS.bat`** फ़ाइल पर डबल-क्लिक करें।
5. **अनुमति दें:**
   - फ़ोन की स्क्रीन पर एक पॉपअप आएगा: *"Allow USB debugging?"*।
   - **"Always allow from this computer"** के बॉक्स पर टिक करें और **Allow** पर टैप करें।
6. **इंस्टॉल पूरा करें:** कंप्यूटर स्क्रीन पर `Y` दबाएं। ऐप सुरक्षित रूप से इंस्टॉल हो जाएगा।

---

### तरीका 2: वायरलेस QR कोड ट्रांसफर (बिना किसी केबल के)
*इसके लिए फ़ोन और कंप्यूटर का एक ही Wi-Fi नेटवर्क से जुड़ा होना आवश्यक है।*

1. **सर्वर शुरू करें:** कंप्यूटर में `D:\bit defender\` में जाकर **`START_QR_INSTALLATION.bat`** पर डबल-क्लिक करें।
2. **QR कोड स्कैन करें:** अपने फ़ोन का कैमरा या Google Lens खोलें और कंप्यूटर स्क्रीन पर दिख रहे QR कोड को स्कैन करें।
3. **डाउनलोड करें:** स्क्रीन पर आए लिंक पर टैप करें और **'Download Official APK'** बटन दबाएं।
4. **इंस्टॉल करें:** डाउनलोड पूरा होने के बाद फ़ाइल पर टैप करें। यदि फ़ोन 'Install unknown apps' की अनुमति मांगे, तो उसे Allow करें और **Install** दबाएं।

---

### तरीका 3: मैन्युअल फ़ाइल कॉपी
1. कंप्यूटर से `D:\bit defender\build\staging_android\BI_Antivirus_Enterprise_v1.1.0.apk` फ़ाइल को पेनड्राइव, ब्लूटूथ, गूगल ड्राइव या USB से अपने फ़ोन के **Download** फ़ोल्डर में भेजें।
2. फ़ोन में **Files / File Manager** खोलें और APK पर टैप करके इंस्टॉल करें।

---

# Manufacturer Battery Optimization Settings

Android manufacturers implement aggressive background process termination. To ensure BI Antivirus continuously protects your device, apply the setting for your brand:

| Manufacturer | Settings Navigation Path | Recommended Setting |
| :--- | :--- | :--- |
| **Samsung (One UI)** | Settings > Battery and device care > Battery > Background usage limits > Never sleeping apps | Add **BI Antivirus** |
| **Xiaomi / Redmi / POCO (MIUI / HyperOS)** | Security app > Manage apps > BI Antivirus > Autostart | Set to **ON** & Battery saver to **No restrictions** |
| **vivo / iQOO (Funtouch / OriginOS)** | Settings > Battery > Background power consumption management > BI Antivirus | Select **Allow high background power consumption** |
| **OnePlus / OPPO / realme (ColorOS / OxygenOS)**| Settings > Battery > More battery settings > Optimize battery use > BI Antivirus | Select **Don't optimize** |
| **Google Pixel / Motorola / Nothing (Stock)** | Settings > Apps > BI Antivirus > App battery usage | Select **Unrestricted** |

---

## First-Run Experience & Storage Access Framework (SAF)

Upon first launch:
1. **Welcome Screen:** Official Black Intel Eagle emblem with sovereign local offline defense guarantee.
2. **Storage Access Permission:** BI Antivirus utilizes Android's privacy-focused **Storage Access Framework (SAF)**. When you tap *"Scan Document"* or *"Scan Directory"*, the native system file picker opens. You choose only the files or folders you want scanned. The app **never** demands broad root or unnecessary device permissions.
3. **Quarantine Vault:** Quarantined items are encrypted with AES-256-GCM using hardware keys from your device's Android Keystore.
