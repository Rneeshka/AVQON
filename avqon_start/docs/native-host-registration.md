    # Регистрация нативного хоста (кратко)

Файлы с конкретными путями и регистрацией разнятся по ОС и браузеру.

## Chrome / Chromium
- Windows: поместите JSON-манифест в:
  `C:\\Users\\<user>\\AppData\\Local\\Google\\Chrome\\NativeMessagingHosts\\com.safebrowse.native.json`
- Linux: `/etc/opt/chrome/native-messaging-hosts/` или `~/.config/google-chrome/NativeMessagingHosts/`.
- macOS: `/Library/Google/Chrome/NativeMessagingHosts/` или `~/Library/Google/Chrome/NativeMessagingHosts/`.

В манифесте укажите абсолютный путь к `native_host.py` и замените `__EXTENSION_ID__` на ID расширения.

## Firefox
- Windows: зарегистрируйте путь к JSON через реестр `HKCU\\Software\\Mozilla\\NativeMessagingHosts\\com.safebrowse.native`.
- Linux/macOS: `~/.mozilla/native-messaging-hosts/` или `/usr/lib/mozilla/native-messaging-hosts/`.

