# portGate 1.0.12

- Панель открывается на английском. Чтобы выбрать русский, откройте **Settings → Interface language**, выберите **Русский** и нажмите **Apply language**.
- Проверка защиты сообщает об изменённом правиле, если Windows Firewall возвращает неподдерживаемый формат адреса. Запись о незавершённом допуске сама по себе больше не прерывает выдачу новых допусков. Оставшиеся правила продолжают проверяться.
- Исправлены подписи событий отката, смены системного времени и отзыва допуска. Неполные команды CLI теперь показывают синтаксис.

Скачайте `portGate-Windows-x64-1.0.12.zip`, сверьте SHA-256 и распакуйте архив целиком. Для обновления закройте установленную панель, запустите `portGate.Manager.exe` из нового архива и выберите **Install** или **Установить**. EXE без Authenticode-подписи. [Руководство администратора](https://github.com/ofdistress2/portGate/blob/v1.0.12/docs/admin-guide.md)

## English

- The panel opens in English. To use Russian, select **Settings → Interface language → Русский → Apply language**.
- The health check reports a modified firewall rule when Windows Firewall returns an unsupported address format. An unfinished grant record alone no longer interrupts new grants. The health check still detects leftover rules.
- Fixed journal labels for incomplete rollback, system clock changes and grant revocation. Incomplete CLI commands now show their usage.

Download `portGate-Windows-x64-1.0.12.zip`, verify its SHA-256 checksum, and extract the full archive. To upgrade, close the installed panel, run `portGate.Manager.exe` from the new archive, and select **Install**. The executables are unsigned. [Administrator guide](https://github.com/ofdistress2/portGate/blob/v1.0.12/docs/admin-guide.en.md)
