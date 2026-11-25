# Как внести вклад

Для обычных ошибок используйте [GitHub Issues](https://github.com/ofdistress2/portGate/issues). Укажите версию portGate, версию и редакцию Windows Server или клиентской ОС, шаги и ожидаемый результат. Уберите из вложений персональные пропуска, ключи, адреса и сведения о рабочей инфраструктуре. Для уязвимостей есть [приватный канал](SECURITY.md).

Соберите проект на Windows командой `.\build.ps1` с .NET 10 SDK. При изменении установки, брандмауэра или восстановления добавьте результаты проверки на отдельной ВМ с консольным доступом. Отправляйте связанные изменения одним pull request.

## Contributing

Use [GitHub Issues](https://github.com/ofdistress2/portGate/issues) for general issues. Include the portGate version, server or client OS version, steps, and expected behavior. Remove client passes, keys, IP addresses, and infrastructure details from attachments. Use the [private reporting channel](SECURITY.md#reporting-a-vulnerability) for security issues.

Build on Windows with the .NET 10 SDK and run `.\build.ps1`. For installer, firewall, or recovery changes, include results from a dedicated VM with console access.
