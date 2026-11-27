# portGate 1.0.14

- Постоянный белый список RDP можно обновлять без перезапуска службы после первого подтверждения защиты. Временные разрешения сохраняются.
- В панели появились боковая навигация, фильтры клиентов и журнала, обновлённые диалоги и масштабирование таблиц.
- Из панели можно окончательно удалить ключ клиента и очистить текущие и архивные записи журнала.

Для установки или обновления распакуйте весь архив и запустите `portgate.Manager.exe`. При переходе со старой службы `KnockGate` выполните перенос данных по руководству администратора. [Руководство администратора](https://github.com/ofdistress2/portGate/blob/v1.0.14/docs/admin-guide.md)

Сверьте SHA-256 ZIP после скачивания. Исполняемые файлы без подписи Authenticode.

## English

- Update the permanent RDP allowlist after confirming protection, without restarting the service. Existing temporary grants retain their expiry.
- The management panel adds sidebar navigation, client and journal filters, refreshed dialogs, and DPI-aware table sizing.
- Administrators can permanently delete a client key and clear current and archived journal entries from the panel.

To install or upgrade, extract the entire ZIP and run `portgate.Manager.exe`. When migrating from the older `KnockGate` service, follow the data migration steps in the guide. [Administrator guide](https://github.com/ofdistress2/portGate/blob/v1.0.14/docs/admin-guide.en.md)

Verify the ZIP's SHA-256 after downloading. The executables are unsigned.
