# portGate 1.0.13

- Исполняемые файлы `portgate.Manager.exe` и `portgate.Host.exe`, служба Windows, системные папки и задачи используют имя `portgate`.
- Служба устанавливается в `C:\Program Files\portgate`. Настройки, ключи и состояние хранятся в `%ProgramData%\portgate`.

Для перехода с установленной службы `KnockGate` требуется перенос данных и повторное применение защиты. Подготовьте консольный доступ. Для новой установки распакуйте весь архив и запустите `portgate.Manager.exe`. [Руководство администратора](https://github.com/ofdistress2/portGate/blob/v1.0.13/docs/admin-guide.md)

Сверьте SHA-256 ZIP после скачивания. EXE без Authenticode-подписи.

## English

- The executables, Windows service, installation and data folders, and scheduled tasks use the `portgate` name.
- The service runs from `C:\Program Files\portgate`. Settings, keys, and state live in `%ProgramData%\portgate`.

When upgrading from the old `KnockGate` service, migrate your data and reapply the firewall policy during a maintenance window with console access. For a fresh installation, extract the entire ZIP and run `portgate.Manager.exe`. [Administrator guide](https://github.com/ofdistress2/portGate/blob/v1.0.13/docs/admin-guide.en.md)

Verify the ZIP's SHA-256 after downloading. The executables are unsigned.
