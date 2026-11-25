using System.Security;
using Microsoft.Win32;

namespace portGate.Manager;

internal enum InterfaceLanguage { English, Russian }

internal static class PanelLanguage
{
    private const string RegistryPath = @"Software\portGate";
    private const string Preference = "InterfaceLanguage";

    internal static InterfaceLanguage Current { get; private set; } = Read();
    internal static string T(string russian, string english) =>
        Current == InterfaceLanguage.Russian ? russian : english;

    private static InterfaceLanguage Read()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RegistryPath);
            return key?.GetValue(Preference) is "ru" ? InterfaceLanguage.Russian : InterfaceLanguage.English;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException)
        {
            return InterfaceLanguage.English;
        }
    }

    internal static void Save(InterfaceLanguage language)
    {
        using var key = Registry.CurrentUser.CreateSubKey(RegistryPath);
        key.SetValue(Preference, language == InterfaceLanguage.Russian ? "ru" : "en");
        Current = language;
    }

    // Translate presentation only. The service and its machine-readable state keep their existing format.
    private static readonly Dictionary<string, string> ServiceMessages = new(StringComparer.Ordinal)
    {
        ["Не настроено"] = "Not configured",
        ["Неизвестно"] = "Unknown",
        ["RDP ограничен по IP"] = "RDP is restricted by IP",
        ["Восстанавливаются прежние правила"] = "Restoring the previous rules",
        ["Применение и проверка правил"] = "Applying and checking firewall rules",
        ["Служба остановлена; актуальность политики не проверена"] = "The service is stopped. Firewall policy has not been verified.",
        ["Ожидается подтверждение нового RDP-сеанса"] = "Waiting for confirmation from a new RDP session",
        ["Проверка политики выполняется"] = "Checking the firewall policy",
        ["Состояние политики изменилось; требуется новая проверка"] = "The firewall policy changed and needs to be checked again",
        ["Защита нарушена: правило авторизации изменено"] = "Protection interrupted: the authorization rule changed",
        ["Защита нарушена: белый список изменён"] = "Protection interrupted: the allowlist changed",
        ["Защита нарушена: временное правило изменено"] = "Protection interrupted: a temporary rule changed",
        ["Защита нарушена: неизвестное собственное правило"] = "Protection interrupted: unrecognized portGate rule",
        ["Политика подтверждена."] = "The policy was confirmed.",
        ["Прежние правила восстановлены."] = "The previous firewall rules were restored.",
        ["Временные разрешения отозваны."] = "Temporary grants were revoked.",
        ["Разрешение отозвано. Клиент может запросить доступ заново."] = "The grant was revoked. The client can request access again.",
        ["Доступ отозван."] = "Access revoked.",
        ["Ключ перевыпущен. Старые скрипты недействительны."] = "The key was rotated. Existing scripts are no longer valid.",
        ["Клиент изменён."] = "The client was updated.",
        ["Настройки сохранены. Адрес и окна доступа действуют для новых скриптов и запросов; существующие разрешения сохраняют свой срок. При изменении сети перезапустите службу перед применением."] =
            "Settings saved. The address and access windows apply to new scripts and requests. Existing grants retain their expiry. Restart the service before applying network changes.",
        ["Слушатель авторизации запущен."] = "The authorization listener started.",
        ["Перед применением правил установите службу кнопкой «Установить»."] = "Select Install to install the service before applying rules.",
        ["Служба ещё не установлена. Сначала нажмите «Установить»."] = "Select Install to install the service first.",
        ["Закройте установленную панель portGate перед обновлением. Новую панель из распакованного ZIP можно оставить открытой."] =
            "Close the installed portGate panel before upgrading. You can leave the panel from the extracted ZIP open.",
        ["Для изменения сети или правил сначала восстановите прежние правила. Адрес сервера и окна доступа можно менять без восстановления."] =
            "Restore the previous rules before changing network settings or firewall rules. You can change the server address and access windows at any time.",
        ["Некорректное имя."] = "Invalid name.",
        ["Окно превышает допустимые пределы."] = "The access window is outside the allowed range.",
    };

    private static readonly (string Russian, string English)[] DetailPrefixes =
    [
        ("Правила применены. Подтвердите из нового RDP-сеанса до ", "Rules applied. Confirm from a new RDP session before "),
        ("Откат не завершён. ", "Rollback is incomplete. "),
        ("Защита нарушена: ", "Protection interrupted: "),
        ("Локальная доступность авторизации не подтверждена. ", "Local authorization could not be verified. "),
        ("Точечный запрет UDP-авторизации сохранится. ", "The scoped UDP authorization block will remain in place. "),
        ("Неизвестный динамический транспорт, требуется проверка: ", "Review the rule with an unknown dynamic transport: "),
        ("Неизвестный фильтр порта, требуется проверка: ", "Review the rule with an unknown port filter: "),
        ("Не удалось определить источники разрешения RDP: ", "The source addresses allowed for RDP could not be determined: "),
        ("Разрешение RDP для заданных источников сохранится. Доступ для них по этому правилу не требует стука: ", "This existing RDP rule will continue to allow its listed sources: "),
        ("Внешняя/доменная политика разрешает RDP: ", "An external or domain policy allows RDP: "),
        ("Локальное правило не найдено по уникальному идентификатору: ", "No local rule matched the unique identifier: "),
        ("Локальное и действующее правило различаются: ", "The local and effective rules differ: "),
        ("Широкое разрешение включает RDP; автоматическое отключение затронет другие службы: ", "A broad allow rule covers RDP and other services: "),
        ("Явный запрет затрагивает RDP: ", "An explicit block affects RDP: "),
        ("Не удалось определить область действия запрета RDP: ", "The scope of an RDP block could not be determined: "),
        ("Существующий запрет сохранится. Указанные адреса могут не получить доступ к RDP после авторизации: ", "The existing block will remain. The specified addresses may still be denied RDP after authorization: "),
        ("Приём UDP: ", "UDP receive: "),
    ];

    internal static string DisplayDetail(string detail)
    {
        if (Current == InterfaceLanguage.Russian) return detail;
        if (ServiceMessages.TryGetValue(detail, out string? translated)) return translated;
        foreach (var (russian, english) in DetailPrefixes)
            if (detail.StartsWith(russian, StringComparison.Ordinal)) return english + detail[russian.Length..];
        return detail;
    }
}
