# portGate 1.0.11

Первая версия portGate с открытым исходным кодом. Основана на сборке 1.0.11, прошедшей двухдневный пилот на Windows RDP-сервере. В ходе пилота проверены установка, остановка, перезапуск и откат.

- `portGate-Windows-x64-1.0.11.zip` содержит сервер Windows и панель управления. Распакуйте ZIP целиком и запустите `portGate.Manager.exe`.
- Для macOS экспортируйте персональный клиентский пропуск из панели Windows.
- Для обновления закройте установленную панель, распакуйте новый ZIP отдельно и нажмите «Установить» в новой панели. Системные имена и пути пилотной установки используются для сохранения существующих данных и привязок.
- Файл `.sha256` содержит SHA-256 ZIP. EXE этой сборки не имеют Authenticode-подписи.

См. [руководство администратора](https://github.com/ofdistress2/portGate/blob/v1.0.11/docs/admin-guide.md).

## English

The first open-source portGate release is based on version 1.0.11, which completed a two-day pilot on a Windows RDP server. The pilot covered installation, stopping, restarting, and rollback.

- `portGate-Windows-x64-1.0.11.zip` includes the Windows service and its Russian-language management panel. Extract the full ZIP and run `portGate.Manager.exe`.
- For macOS, export a personal client pass from the Windows application.
- To upgrade, close the installed panel, extract the new ZIP separately, and select **Установить** (Install). The package keeps the existing data directory and service identifiers.
- The `.sha256` file contains the ZIP's SHA-256 checksum. The EXE files are unsigned.

See the [English administrator guide](https://github.com/ofdistress2/portGate/blob/main/docs/admin-guide.en.md).
