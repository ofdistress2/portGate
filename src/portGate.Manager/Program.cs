using System.Text.Json;
using portGate.Core;
using static portGate.Manager.PanelLanguage;

namespace portGate.Manager;
internal static class Program
{
    [STAThread] private static void Main()
    {
        ApplicationConfiguration.Initialize();
        bool showSettings = false;
        do
        {
            using var panel = new MainForm(showSettings);
            Application.Run(panel);
            showSettings = panel.LanguageChanged;
        } while (showSettings);
    }
}
internal sealed class MainForm : Form
{
    private readonly Label serviceStatus = new() { AutoSize = true, Text = T("Служба: получение состояния…", "Service: checking status…") };
    private readonly Label protectionStatus = new() { AutoSize = true, Text = T("Защита: получение состояния…", "Protection: checking status…"), MaximumSize = new Size(700, 0) };
    private readonly Label connectionStatus = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Label confirmation = new() { AutoSize = true, Visible = false, MaximumSize = new Size(700, 0), Padding = new Padding(8) };
    private readonly Label operationTitle = new() { AutoSize = true, Text = T("Последнее действие", "Latest action") };
    private readonly Label operationDetail = new() { AutoSize = true, Text = T("Действий пока не выполняли.", "No actions yet."), MaximumSize = new Size(700, 0) };
    private readonly FlowLayoutPanel operation = new() { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(10), Margin = new Padding(3, 8, 3, 8) };
    private readonly Dictionary<Button, Func<bool>> overviewActions = [];
    private readonly List<Button> clientActions = [];
    private string? currentService;
    private bool? policyConfigured;
    private bool? awaitingConfirmation;
    private bool? hasTrustedSources;
    private TimeSpan? confirmationWindow;
    private long confirmationSample;
    private enum Notice { Working, Success, Attention, Error, Cancelled }
    private readonly ToolStripStatusLabel message = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly DataGridView clients = Grid();
    private readonly DataGridView leases = Grid();
    private readonly Label journalStatus = new() { AutoSize = true, Text = T("Журнал ещё не загружен.", "The journal has not been loaded.") };
    private readonly DataGridView events = Grid();
    private readonly Label planSummary = new() { AutoSize = true, Text = T("Нажмите «Проверить правила», чтобы увидеть результат.", "Select Check rules to see the result.") };
    private FirewallPlan? latestPlan;
    private readonly NumericUpDown port = Number(1024, 65535, 51888);
    private readonly DurationInput duration = new(300);
    private readonly DurationInput maximumDuration = new(86400);
    private readonly TextBox serverAddress = new() { Width = 650 };
    private readonly TextBox trusted = new() { Multiline = true, Height = 90, Width = 650, ScrollBars = ScrollBars.Vertical };
    private readonly Label trustedHint = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private Config? config;
    private string? previousClients, previousLeases;
    private bool busy;
    private CancellationTokenSource? backgroundRefresh;
    private bool settingsDirty, loadingSettings;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 15000 };
    private readonly System.Windows.Forms.Timer countdown = new() { Interval = 1000 };
    internal bool LanguageChanged { get; private set; }

    public MainForm(bool showSettings = false)
    {
        Text = "portGate " + typeof(MainForm).Assembly.GetName().Version?.ToString(3) + T(" — управление доступом RDP", " — RDP access management"); MinimumSize = new Size(800, 650); Size = new Size(1000, 780);
        Font = new Font("Segoe UI", 10); AutoScaleMode = AutoScaleMode.Dpi; StartPosition = FormStartPosition.CenterScreen;
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var overview = Page(tabs, T("Обзор", "Overview"));
        var currentStatus = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(8), BackColor = SystemColors.Window };
        serviceStatus.Font = new Font(Font, FontStyle.Bold);
        protectionStatus.Font = new Font(Font, FontStyle.Bold);
        currentStatus.Controls.AddRange([serviceStatus, protectionStatus, connectionStatus]);
        overview.Controls.Add(currentStatus);
        confirmation.Font = new Font(Font, FontStyle.Bold);
        confirmation.BackColor = SystemColors.Window;
        overview.Controls.Add(confirmation);
        Heading(overview, T("Служба", "Service"));
        var service = Row(overview);
        foreach (var (caption, title, command, expectedState, success) in new[]
        {
            (T("Установить", "Install"), T("Установка службы", "Install service"), "install", "Installed", T("Служба установлена. Запустите её кнопкой «Запустить».", "Service installed. Select Start to run it.")),
            (T("Запустить", "Start"), T("Запуск службы", "Start service"), "start", "Running", T("Служба запущена.", "The service is running.")),
            (T("Остановить", "Stop"), T("Остановка службы", "Stop service"), "stop", "Stopped", T("Служба остановлена.", "The service has stopped.")),
            (T("Перезапустить", "Restart"), T("Перезапуск службы", "Restart service"), "restart", "Running", T("Служба перезапущена.", "The service restarted."))
        })
            OverviewButton(service, caption, title, async () =>
            {
                await Local(command);
                return await VerifyServiceState(expectedState, success);
            }, refresh: false, available: () => currentService switch
            {
                null or "" => true,
                "Не установлена" => command == "install",
                "Stopped" => command is "install" or "start",
                "Running" or "Paused" => command is "install" or "stop" or "restart",
                _ => false
            });
        OverviewButton(service, T("Удалить…", "Uninstall…"), T("Удаление службы", "Uninstall service"), async () =>
        {
            var answer = MessageBox.Show(this, T("Восстановить прежние правила?\nДа — восстановить. Нет — оставить постоянный белый список. Отмена — ничего не делать.", "Restore the previous firewall rules?\nYes restores the rules. No keeps the permanent allowlist. Cancel leaves the service installed."), T("Удаление службы", "Uninstall service"), MessageBoxButtons.YesNoCancel, MessageBoxIcon.Question);
            if (answer == DialogResult.Cancel) return (Notice.Cancelled, T("Удаление отменено.", "Uninstall cancelled."));
            await Local("uninstall", answer == DialogResult.Yes ? "--restore" : "--keep-trusted");
            return await VerifyServiceState("Не установлена", T("Служба удалена.", "The service was removed."));
        }, refresh: false, available: () => currentService is null or "Stopped" or "Running" or "Paused");
        Heading(overview, T("Защита RDP", "RDP protection"));
        var policy = Row(overview);
        OverviewButton(policy, T("Проверить правила", "Check rules"), T("Проверка правил", "Check firewall rules"), async () =>
        {
            var p = await ReadPlan();
            if (!p.Safe) return (Notice.Attention, T($"Найдено конфликтов: {p.Conflicts.Count}. Откройте подробности плана.", $"Found {p.Conflicts.Count} conflicts. Open the plan details for more information."));
            return (p.Warnings.Count > 0 ? Notice.Attention : Notice.Success, T($"Конфликтов нет. Правил к отключению: {p.Disable.Count}. Предупреждений: {p.Warnings.Count}.", $"No conflicts. Rules to disable: {p.Disable.Count}. Warnings: {p.Warnings.Count}."));
        });
        OverviewButton(policy, T("Применить защиту…", "Apply protection…"), T("Применение защиты", "Apply protection"), async () =>
        {
            var p = await ReadPlan();
            if (!p.Safe) return (Notice.Error, T($"Применение остановлено. {DisplayDetail(p.Conflicts[0])}", $"Unable to apply protection. {DisplayDetail(p.Conflicts[0])}"));
            if (!ShowPlan(p, confirmApply: true))
                return (Notice.Cancelled, T("Применение отменено.", "Applying protection was cancelled."));
            return (Notice.Attention, await Request("apply"));
        }, available: () => currentService != "Не установлена" && policyConfigured != true && hasTrustedSources != false);
        OverviewButton(policy, T("Подтвердить новый вход", "Confirm new sign-in"), T("Подтверждение нового входа", "Confirm new RDP sign-in"),
            async () => (Notice.Success, await Request("confirm")), available: () => awaitingConfirmation == true && ConfirmationRemaining() is { Ticks: > 0 });
        OverviewButton(policy, T("Восстановить правила…", "Restore rules…"), T("Восстановление правил", "Restore firewall rules"), async () =>
        {
            if (!Confirm(T("Восстановить правила, изменённые portGate?", "Restore the rules changed by portGate?"))) return (Notice.Cancelled, T("Восстановление отменено.", "Restore cancelled."));
            return (Notice.Success, await Request("restore"));
        }, available: () => policyConfigured != false);
        operationTitle.Font = new Font(Font, FontStyle.Bold);
        operation.BackColor = SystemColors.Window;
        operation.Controls.AddRange([operationTitle, operationDetail]);
        overview.Controls.Add(operation);
        Heading(overview, T("План правил", "Firewall plan"));
        overview.Controls.Add(planSummary);
        var planDetails = Button(Row(overview), T("Подробности плана…", "Plan details…"), () =>
        {
            if (latestPlan is { } snapshot) ShowPlan(snapshot, confirmApply: false);
            return Task.CompletedTask;
        });
        overviewActions.Add(planDetails, () => latestPlan != null);
        Heading(overview, T("Временные разрешения", "Temporary grants"));
        overview.Controls.Add(new Label { Text = T("Отзыв разрешения не завершает уже открытый RDP-сеанс.", "Revoking a grant leaves existing RDP sessions open."), AutoSize = true });
        overview.Controls.Add(leases);
        var leaseActions = Row(overview);
        OverviewButton(leaseActions, T("Отозвать выбранное…", "Revoke selected…"), T("Отзыв разрешения", "Revoke grant"), async () =>
        {
            string id = SelectedKey(leases, "ruleId") ?? throw new InvalidOperationException(T("Выберите разрешение.", "Select a grant."));
            if (!Confirm(T("Отозвать выбранное разрешение? Ключ останется действующим, клиент сможет запросить доступ заново.", "Revoke the selected grant? The key stays valid and the client can request access again.")))
                return (Notice.Cancelled, T("Отзыв отменён.", "Revocation cancelled."));
            return (Notice.Success, await Request("lease-revoke", id));
        }, available: () => SelectedKey(leases, "ruleId") != null);
        OverviewButton(leaseActions, T("Отозвать все временные разрешения", "Revoke all temporary grants"), T("Отзыв временных разрешений", "Revoke temporary grants"),
            async () => (Notice.Success, await Request("leases-revoke")), available: () => leases.Rows.Count > 0);
        leases.SelectionChanged += (_, _) => RefreshOverviewActions();
        var access = Page(tabs, T("Клиенты доступа", "Clients"));
        access.Controls.Add(new Label { Text = T("Один скрипт = один пропуск. Передавайте файл только его владельцу.", "Each script is an access pass. Share the file only with its owner."), AutoSize = true });
        access.Controls.Add(clients);
        var tools = Row(access);
        Button(tools, T("Создать и сохранить скрипт…", "Create and save script…"), CreateClient);
        clientActions.Add(Button(tools, T("Сохранить скрипт…", "Save script…"), async () => await Export(SelectedId())));
        clientActions.Add(Button(tools, T("Отозвать", "Revoke"), async () => { if (Confirm(T("Отозвать доступ и временные разрешения клиента?", "Revoke the client's access and temporary grants?"))) { message.Text = DisplayDetail(await Request("clients-revoke", SelectedId())); await RefreshData(); } }));
        clientActions.Add(Button(tools, T("Перевыпустить ключ", "Rotate key"), async () => { if (Confirm(T("Старые скрипты перестанут работать. Перевыпустить ключ?", "Existing scripts will stop working. Rotate the key?"))) { message.Text = DisplayDetail(await Request("clients-rotate", SelectedId())); await RefreshData(); } }));
        clientActions.Add(Button(tools, T("Изменить имя и срок…", "Edit name and duration…"), async () =>
        {
            string id = SelectedId();
            var existing = Json.Read<List<ClientRecord>>(await Request("clients-list")).Single(c => c.Id == id);
            using var dialog = new ClientDialog(false, Json.Read<Config>(await Request("config")), existing);
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            message.Text = DisplayDetail(await Request("clients-edit", id, dialog.ClientName, dialog.Expiry, dialog.Seconds.ToString())); await RefreshData();
        }));
        clients.SelectionChanged += (_, _) => RefreshClientActions();
        clients.CellFormatting += (_, e) =>
        {
            if (e.RowIndex >= 0 && e.RowIndex < clients.Rows.Count && clients.Columns.Contains("active") &&
                clients.Rows[e.RowIndex].Cells["active"].Value?.ToString() == T("Нет", "No"))
                e.CellStyle!.ForeColor = SystemColors.GrayText;
        };
        var settings = Page(tabs, T("Настройки", "Settings"));
        var languageRow = Row(settings);
        languageRow.Controls.Add(new Label { AutoSize = true, Text = T("Язык интерфейса", "Interface language") });
        var languages = new ComboBox
        {
            Name = "interfaceLanguage",
            AccessibleName = T("Язык интерфейса", "Interface language"),
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 155
        };
        languages.Items.AddRange(["English", "Русский"]);
        languages.SelectedIndex = Current == InterfaceLanguage.Russian ? 1 : 0;
        languageRow.Controls.Add(languages);
        var applyLanguage = new Button
        {
            Name = "applyLanguage",
            Text = T("Применить язык", "Apply language"),
            AutoSize = true,
            Enabled = false
        };
        languageRow.Controls.Add(applyLanguage);
        languages.SelectedIndexChanged += (_, _) => applyLanguage.Enabled = SelectedLanguage() != Current;
        InterfaceLanguage SelectedLanguage() => languages.SelectedIndex == 1 ? InterfaceLanguage.Russian : InterfaceLanguage.English;
        applyLanguage.Click += (_, _) =>
        {
            if (busy || SelectedLanguage() == Current) return;
            if (settingsDirty && !Confirm(T(
                "Смена языка перезапустит панель и сбросит несохранённые изменения формы. Продолжить?",
                "Changing the language will reopen the panel and discard unsaved form changes. Continue?"))) return;
            try { Save(SelectedLanguage()); }
            catch (Exception error) when (error is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                MessageBox.Show(this, error.Message, T("Язык не сохранён", "Could not save the language"),
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            settingsDirty = false;
            LanguageChanged = true;
            Close();
        };

        settings.Controls.Add(new Label { AutoSize = true, Text = T("Внешний IP или DNS сервера для скриптов доступа", "Public server IP or DNS name for access scripts") }); settings.Controls.Add(serverAddress);
        settings.Controls.Add(new Label { AutoSize = true, Text = T("Порт UDP авторизации", "UDP authorization port") }); settings.Controls.Add(port);
        settings.Controls.Add(new Label { AutoSize = true, Text = T("Окно доступа по умолчанию (24 часа = переподключение в течение суток)", "Default access window (24 hours allows reconnection for one day)") }); settings.Controls.Add(duration);
        settings.Controls.Add(new Label { AutoSize = true, Text = T("Максимальное окно доступа клиента (до 7 суток)", "Maximum client access window (up to 7 days)") }); settings.Controls.Add(maximumDuration);
        settings.Controls.Add(new Label { AutoSize = true, Text = T("Постоянный белый список RDP: IP или CIDR, по одному на строку", "Permanent RDP allowlist (one IP address or CIDR per line)") });
        settings.Controls.Add(trustedHint);
        settings.Controls.Add(trusted);
        var settingsActions = Row(settings);
        Button(settingsActions, T("Сохранить настройки", "Save settings"), async () =>
        {
            config ??= Json.Read<Config>(await Request("config"));
            var next = Json.Read<Config>(Json.Write(config));
            next.UdpPort = (int)port.Value; next.LeaseSeconds = duration.Seconds; next.MaxLeaseSeconds = maximumDuration.Seconds;
            next.ServerAddress = serverAddress.Text.Trim();
            next.TrustedRdpCidrs = trusted.Lines.Select(x => x.Trim()).Where(x => x != "").ToArray();
            next.Validate();
            message.Text = DisplayDetail(await Request("config-save", Json.Write(next)));
            settingsDirty = false; await RefreshData();
        });
        Button(settingsActions, T("Отменить изменения", "Discard changes"), async () =>
        {
            if (!settingsDirty || !Confirm(T("Загрузить сохранённые настройки и отбросить изменения формы?", "Reload saved settings and discard changes on this form?"))) return;
            settingsDirty = false;
            await RefreshData();
        });
        Button(settingsActions, T("Расширенные настройки (JSON)…", "Advanced settings (JSON)…"), EditJsonConfig);
        settings.Controls.Add(new Label { AutoSize = true, Text = T("Адрес и окна доступа сохраняются без перезапуска. Для изменения сети/правил сначала восстановите прежнюю политику.", "You can save the address and access windows without restarting. Restore the existing policy before changing network or firewall rules.") });
        void Dirty() { if (!loadingSettings) settingsDirty = true; }
        serverAddress.TextChanged += (_, _) => Dirty(); trusted.TextChanged += (_, _) => Dirty(); port.ValueChanged += (_, _) => Dirty();
        duration.Changed += Dirty; maximumDuration.Changed += Dirty;
        var journal = Page(tabs, T("Журнал", "Journal"));
        var journalTools = Row(journal);
        Button(journalTools, T("Обновить журнал", "Refresh journal"), RefreshJournal);
        journal.Controls.Add(journalStatus);
        events.Height = 440;
        events.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        events.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.DisplayedCellsExceptHeaders;
        journal.Controls.Add(events);
        var bottom = new StatusStrip { SizingGrip = false };
        bottom.Items.Add(message);
        Controls.Add(tabs); Controls.Add(bottom);
        if (showSettings && settings.Parent is TabPage settingsTab) tabs.SelectedTab = settingsTab;
        Shown += async (_, _) => await Guard(RefreshData);
        tabs.SelectedIndexChanged += async (_, _) =>
        {
            if (busy) return;
            if (settings.Parent == tabs.SelectedTab) await Guard(RefreshData);
            if (journal.Parent == tabs.SelectedTab) await Guard(RefreshJournal);
        };
        timer.Tick += async (_, _) => await RefreshInBackground();
        timer.Start();
        countdown.Tick += (_, _) => UpdateCountdown();
        RefreshOverviewActions();
        RefreshClientActions();
        FormClosing += (_, e) => { if (settingsDirty && !Confirm(T("Закрыть окно без сохранения настроек?", "Close the window without saving your settings?"))) e.Cancel = true; };
        FormClosed += (_, _) => { timer.Dispose(); countdown.Dispose(); backgroundRefresh?.Cancel(); };
    }
    private static NumericUpDown Number(int min, int max, int value) => new() { Minimum = min, Maximum = max, Value = value, Width = 150 };
    private static DataGridView Grid() => new() { Height = 165, ReadOnly = true, AllowUserToAddRows = false, AllowUserToDeleteRows = false, MultiSelect = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect, AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.DisplayedCells, RowHeadersVisible = false, BorderStyle = BorderStyle.Fixed3D, BackgroundColor = SystemColors.Window };
    private static FlowLayoutPanel Page(TabControl tabs, string title)
    {
        var page = new TabPage(title);
        var flow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, AutoScroll = true, Padding = new Padding(14) };
        flow.SizeChanged += (_, _) => FitPage(flow);
        flow.ControlAdded += (_, _) => FitPage(flow);
        page.Controls.Add(flow);
        tabs.TabPages.Add(page);
        return flow;
    }
    private static void FitPage(FlowLayoutPanel page)
    {
        int width = Math.Max(100, page.ClientSize.Width - page.Padding.Horizontal - SystemInformation.VerticalScrollBarWidth - 8);
        foreach (Control child in page.Controls)
        {
            if (child is FlowLayoutPanel row)
            {
                row.MaximumSize = new Size(width, 0);
                if (row.FlowDirection == FlowDirection.TopDown)
                {
                    row.MinimumSize = new Size(width, 0);
                    foreach (Label text in row.Controls.OfType<Label>())
                        text.MaximumSize = new Size(Math.Max(80, width - row.Padding.Horizontal - 8), 0);
                }
            }
            else if (child is DataGridView or TextBox) child.Width = width;
            else if (child is Label label) label.MaximumSize = new Size(width, 0);
        }
    }
    private static void Heading(Control parent, string title)
    {
        parent.Controls.Add(new Label { Text = title, Font = new Font(parent.Font, FontStyle.Bold), AutoSize = true, Margin = new Padding(3, 10, 3, 1) });
    }
    private static FlowLayoutPanel Row(Control parent)
    {
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = true };
        parent.Controls.Add(row);
        return row;
    }
    private Button Button(Control parent, string text, Func<Task> action)
    {
        var button = new Button { Text = text, AutoSize = true, Padding = new Padding(5), Margin = new Padding(3) };
        button.Click += async (_, _) => { if (!busy) await Guard(action); }; parent.Controls.Add(button);
        return button;
    }
    private void OverviewButton(Control parent, string caption, string title, Func<Task<(Notice State, string Detail)>> action, bool refresh = true, Func<bool>? available = null)
    {
        var button = Button(parent, caption, async () =>
        {
            ShowOperation(title, Notice.Working, T("Ожидаем завершения операции…", "Waiting for the operation to finish…"));
            try
            {
                var (state, detail) = await action();
                ShowOperation(title, state, detail);
            }
            catch (Exception e)
            {
                ShowOperation(title, Notice.Error, e.Message);
            }
            finally
            {
                try { if (refresh) await RefreshStatus(); }
                catch (Exception e) { ShowRefreshError(e); }
            }
        });
        overviewActions.Add(button, available ?? (() => true));
    }
    private void RefreshOverviewActions()
    {
        foreach (var (button, isAvailable) in overviewActions)
            button.Enabled = !busy && isAvailable();
    }
    private void RefreshClientActions()
    {
        bool selected = !busy && SelectedKey(clients, "id") != null;
        foreach (var button in clientActions) button.Enabled = selected;
    }
    private TimeSpan? ConfirmationRemaining() => confirmationWindow - System.Diagnostics.Stopwatch.GetElapsedTime(confirmationSample);
    private void UpdateCountdown()
    {
        bool visible = awaitingConfirmation == true && ConfirmationRemaining().HasValue;
        confirmation.Visible = visible;
        if (!visible)
        {
            countdown.Stop();
            return;
        }
        var remaining = ConfirmationRemaining()!.Value;
        confirmation.ForeColor = StatusColor(remaining.TotalSeconds <= 30 ? Color.DarkRed : Color.SaddleBrown);
        if (remaining > TimeSpan.Zero)
        {
            int seconds = (int)Math.Ceiling(remaining.TotalSeconds);
            confirmation.Text = T($"До окончания подтверждения {seconds / 60:00}:{seconds % 60:00}\nВойдите в новый RDP-сеанс с адреса из белого списка. В нём откройте portGate и подтвердите вход.", $"Confirmation expires in {seconds / 60:00}:{seconds % 60:00}\nOpen a new RDP session from an allowlisted address. Open portGate in that session and confirm the sign-in.");
            if (!countdown.Enabled) countdown.Start();
        }
        else
        {
            confirmation.Text = T("Время подтверждения истекло. Ожидается обновление состояния правил.", "The confirmation window expired. Waiting for firewall status to refresh.");
            countdown.Stop();
        }
        RefreshOverviewActions();
    }
    private void ShowOperation(string title, Notice state, string detail)
    {
        string label = state switch
        {
            Notice.Working => T("Выполняется", "Working"),
            Notice.Success => T("Готово", "Done"),
            Notice.Attention => T("Требуется внимание", "Attention required"),
            Notice.Error => T("Ошибка", "Error"),
            _ => T("Отменено", "Cancelled")
        };
        operationTitle.Text = $"{label} — {title} · {DateTime.Now:HH:mm:ss}";
        operationDetail.Text = DisplayDetail(detail);
        operationTitle.ForeColor = state switch
        {
            Notice.Success => StatusColor(Color.DarkGreen),
            Notice.Attention => StatusColor(Color.SaddleBrown),
            Notice.Error => StatusColor(Color.DarkRed),
            _ => SystemColors.WindowText
        };
    }
    private static Color StatusColor(Color color) => SystemInformation.HighContrast ? SystemColors.WindowText : color;
    private async Task<FirewallPlan> ReadPlan()
    {
        latestPlan = null;
        planSummary.Text = T("Проверяются действующие правила брандмауэра…", "Checking active firewall rules…");
        FirewallPlan result;
        try { result = Json.Read<FirewallPlan>(await Request("plan")); }
        catch
        {
            planSummary.Text = T("План недоступен. Подробности ошибки показаны в результате операции.", "The plan is unavailable. See the operation result for details.");
            throw;
        }
        latestPlan = result;
        planSummary.Text = (result.Safe ? T("План готов", "Plan ready") : T("Обнаружены конфликты", "Conflicts found")) +
            T($" · порт RDP {result.RdpPort}\n", $" · RDP port {result.RdpPort}\n") +
            T($"Правил к отключению: {result.Disable.Count}   •   Предупреждений: {result.Warnings.Count}   •   Конфликтов: {result.Conflicts.Count}", $"Rules to disable: {result.Disable.Count}   •   Warnings: {result.Warnings.Count}   •   Conflicts: {result.Conflicts.Count}");
        planSummary.ForeColor = result.Safe ? SystemColors.ControlText : StatusColor(Color.DarkRed);
        return result;
    }
    private bool ShowPlan(FirewallPlan snapshot, bool confirmApply)
    {
        using var dialog = new Form
        {
            Text = confirmApply ? T("Проверка перед применением защиты", "Review before applying protection") : T("Подробности плана брандмауэра", "Firewall plan details"),
            ShowInTaskbar = false, Font = Font, AutoScaleMode = AutoScaleMode.Dpi,
            ClientSize = new Size(710, 440), MinimumSize = new Size(500, 320),
            StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, MaximizeBox = false
        };
        var tabs = new TabControl { Dock = DockStyle.Fill };
        void AddDetail(string title, string content, bool wrap)
        {
            var page = new TabPage(title);
            page.Controls.Add(new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = wrap, ReadOnly = true, Text = content });
            tabs.TabPages.Add(page);
        }
        string intro = confirmApply
            ? T("После проверки правил откройте новый RDP-сеанс с адреса из белого списка. На подтверждение даётся 120 секунд. По истечении времени прежние правила будут восстановлены.", "After reviewing the rules, open a new RDP session from an allowlisted address. You have 120 seconds to confirm. The previous rules will be restored if time expires.")
            : T($"Порт RDP: {snapshot.RdpPort}", $"RDP port: {snapshot.RdpPort}");
        string Section(string title, IEnumerable<string> lines)
        {
            string items = string.Join("\r\n", lines.Select(line => "• " + DisplayDetail(line)));
            return $"{title}\r\n{(items.Length == 0 ? T("Нет.", "None.") : items)}";
        }
        AddDetail(T("Сводка", "Summary"), string.Join("\r\n\r\n", intro,
            Section(T("Конфликты", "Conflicts"), snapshot.Conflicts),
            Section(T("Предупреждения", "Warnings"), snapshot.Warnings),
            Section(T("Будут отключены", "Rules to disable"), snapshot.Disable.Select(rule =>
                $"{rule.Name} · {rule.Identity} · {(rule.Protocol == 6 ? "TCP" : rule.Protocol == 17 ? "UDP" : T("протокол ", "protocol ") + rule.Protocol)} {rule.Ports}"))), wrap: true);
        AddDetail(T("Технические данные (JSON)", "Technical data (JSON)"), Json.Write(snapshot), wrap: false);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8), WrapContents = false };
        var close = new Button { Text = confirmApply ? T("Отмена", "Cancel") : T("Закрыть", "Close"), AutoSize = true, DialogResult = DialogResult.Cancel };
        buttons.Controls.Add(close);
        dialog.CancelButton = close;
        if (confirmApply)
        {
            var apply = new Button { Text = T("Применить защиту", "Apply protection"), AutoSize = true, DialogResult = DialogResult.OK };
            buttons.Controls.Add(apply);
        }
        dialog.Controls.Add(tabs);
        dialog.Controls.Add(buttons);
        dialog.Shown += (_, _) => close.Focus();
        return dialog.ShowDialog(this) == DialogResult.OK;
    }
    private async Task<(Notice, string)> VerifyServiceState(string expected, string success)
    {
        string actual;
        try
        {
            actual = (await RefreshStatus()).Service;
        }
        catch (Exception e)
        {
            return (Notice.Attention, T($"Команда завершилась, но подтвердить состояние службы не удалось. {DisplayDetail(e.Message)}", $"The command finished, but the service status could not be verified. {DisplayDetail(e.Message)}"));
        }
        if (expected == "Installed" && actual == "Running") return (Notice.Success, T("Служба обновлена и работает.", "The service was updated and is running."));
        return actual == expected || expected == "Installed" && actual == "Stopped"
            ? (Notice.Success, success)
            : (Notice.Attention, T($"Команда завершилась. Текущее состояние службы: {ServiceLabel(actual)}.", $"The command finished. Current service status: {ServiceLabel(actual)}."));
    }
    private static string ServiceLabel(string state) => state switch
    {
        "Running" => T("Работает", "Running"),
        "Stopped" => T("Остановлена", "Stopped"),
        "StartPending" => T("Запускается", "Starting"),
        "StopPending" => T("Останавливается", "Stopping"),
        "Paused" => T("Приостановлена", "Paused"),
        "PausePending" => T("Приостанавливается", "Pausing"),
        "ContinuePending" => T("Возобновляет работу", "Resuming"),
        "Не установлена" => T("Не установлена", "Not installed"),
        _ => T("Неизвестно", "Unknown")
    };
    private async Task RefreshInBackground()
    {
        if (busy || backgroundRefresh != null) return;
        using var cancellation = new CancellationTokenSource();
        backgroundRefresh = cancellation;
        try { await RefreshStatus(cancellation.Token); }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
        catch (Exception e) { if (!cancellation.IsCancellationRequested && !IsDisposed) ShowRefreshError(e); }
        finally { backgroundRefresh = null; }
    }
    private void ShowRefreshError(Exception error)
    {
        connectionStatus.Text = T("Не удалось полностью обновить данные. ", "Some data could not be refreshed. ") + DisplayDetail(error.Message);
        connectionStatus.ForeColor = StatusColor(Color.DarkRed);
    }
    private async Task Guard(Func<Task> action)
    {
        backgroundRefresh?.Cancel();
        busy = true;
        UseWaitCursor = true;
        RefreshOverviewActions();
        RefreshClientActions();
        try { await action(); }
        catch (Exception e) { message.Text = DisplayDetail(e.Message); MessageBox.Show(this, message.Text, "portGate", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        finally
        {
            busy = false;
            UseWaitCursor = false;
            RefreshOverviewActions();
            RefreshClientActions();
        }
    }
    private static bool Confirm(string text) => MessageBox.Show(text, "portGate", MessageBoxButtons.OKCancel, MessageBoxIcon.Question) == DialogResult.OK;
    private static string? SelectedKey(DataGridView grid, string column) =>
        grid.SelectedRows.Count == 1 && grid.Columns.Contains(column) ? grid.SelectedRows[0].Cells[column].Value?.ToString() : null;
    private string SelectedId() => SelectedKey(clients, "id") ?? throw new InvalidOperationException(T("Выберите клиента.", "Select a client."));
    private static string HostPath(bool installing = false)
    {
        string path = Path.Combine(AppContext.BaseDirectory, Deployment.PackagedHostName);
        bool runningFromInstalledDirectory = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)
            .Equals(Path.GetDirectoryName(Deployment.InstalledHost), StringComparison.OrdinalIgnoreCase);
        if ((!installing || runningFromInstalledDirectory) && File.Exists(Deployment.InstalledHost))
            return Deployment.InstalledHost;
        if (!File.Exists(path)) throw new FileNotFoundException(T("portGate.Host.exe должен находиться рядом с панелью. Используйте папку опубликованной поставки.", "portGate.Host.exe must be available next to the panel. Use the folder from the release archive."));
        return path;
    }
    private async Task<string> Local(string command, params string[] args) => await Task.Run(() => Native.Run(HostPath(command == "install"), new[] { command }.Concat(args), 180000));
    private async Task<string> Request(string command, params string[] args)
    {
        return await LocalRequest(command, args);
    }
    private async Task<string> LocalRequest(string command, string[] args)
    {
        // Pass config JSON through a temporary file, not shell text.
        if (command == "config-save")
        {
            string temp = Path.Combine(Path.GetTempPath(), "kg-" + Guid.NewGuid().ToString("N") + ".json");
            try { File.WriteAllText(temp, args[0]); return await Local(command, temp); } finally { File.Delete(temp); }
        }
        return await Local(command, args);
    }
    private async Task RefreshData()
    {
        var (service, protection) = await RefreshStatus();
        if (service == "Не установлена" && protection == "Не настроено") return;
        if (!settingsDirty)
        {
            config = Json.Read<Config>(await Local("config"));
            loadingSettings = true;
            try { port.Value = config.UdpPort; duration.Seconds = config.LeaseSeconds; maximumDuration.Seconds = config.MaxLeaseSeconds; serverAddress.Text = config.ServerAddress; trusted.Lines = config.TrustedRdpCidrs; }
            finally { loadingSettings = false; }
        }
    }
    private async Task EditJsonConfig()
    {
        if (settingsDirty)
        {
            MessageBox.Show(this, T("Сохраните или отмените изменения формы, затем откройте JSON.", "Save or discard the form changes before opening JSON."), T("Настройки", "Settings"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        string json = await Request("config");
        using var dialog = new Form { Text = T("Расширенные настройки (JSON)", "Advanced settings (JSON)"), Size = new Size(760, 520), StartPosition = FormStartPosition.CenterParent, AutoScaleMode = AutoScaleMode.Dpi };
        bool readOnly = policyConfigured != false;
        var editor = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false, ReadOnly = readOnly, Text = json };
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(8) };
        var close = new Button { Text = T("Закрыть", "Close"), AutoSize = true, DialogResult = DialogResult.Cancel };
        if (!readOnly)
        {
            var save = new Button { Text = T("Сохранить JSON", "Save JSON"), AutoSize = true };
            save.Click += async (_, _) =>
            {
                save.Enabled = close.Enabled = false;
                try
                {
                    var next = Json.Read<Config>(editor.Text);
                    next.Validate();
                    message.Text = DisplayDetail(await Request("config-save", Json.Write(next)));
                    dialog.DialogResult = DialogResult.OK;
                }
                catch (Exception error)
                {
                    MessageBox.Show(dialog, DisplayDetail(error.Message), T("Настройки не сохранены", "Settings could not be saved"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally { save.Enabled = close.Enabled = true; }
            };
            dialog.FormClosing += (_, e) => { if (!save.Enabled && dialog.DialogResult != DialogResult.OK) e.Cancel = true; };
            buttons.Controls.Add(save);
        }
        buttons.Controls.Add(close);
        dialog.Controls.Add(editor);
        dialog.Controls.Add(buttons);
        dialog.CancelButton = close;
        if (dialog.ShowDialog(this) == DialogResult.OK) await RefreshData();
    }
    private async Task RefreshJournal()
    {
        string output = await Local("events");
        var table = new System.Data.DataTable();
        table.Columns.Add(T("Время", "Time"));
        table.Columns.Add(T("Событие", "Event"));
        table.Columns.Add(T("Подробности", "Details"));
        foreach (string line in output.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            if (line == "Событий нет.") continue;
            try
            {
                using var entry = JsonDocument.Parse(line);
                var root = entry.RootElement;
                string? date = root.GetProperty("time").GetString();
                string? kind = root.GetProperty("kind").GetString();
                string? detail = root.GetProperty("detail").GetString();
                table.Rows.Add(DateTimeOffset.TryParse(date, out var time) ? time.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") : date,
                    JournalEvent(kind), detail is null ? null : DisplayDetail(detail));
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
            {
                table.Rows.Add("", T("Не удалось прочитать запись", "Could not read entry"), line);
            }
        }
        events.DataSource = table;
        events.Columns[0].AutoSizeMode = DataGridViewAutoSizeColumnMode.DisplayedCells;
        events.Columns[1].AutoSizeMode = DataGridViewAutoSizeColumnMode.DisplayedCells;
        events.Columns[2].AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        journalStatus.Text = table.Rows.Count == 0 ? T("Событий пока нет.", "No events yet.") : T($"Записей: {table.Rows.Count}. Сначала показаны новые.", $"{table.Rows.Count} entries. Newest first.");
    }
    private static string JournalEvent(string? name) => name switch
    {
        "ServiceStarted" => T("Служба запущена", "Service started"),
        "ServiceStopped" => T("Служба остановлена", "Service stopped"),
        "ServiceFailed" => T("Ошибка службы", "Service error"),
        "AccessGranted" => T("Доступ выдан", "Access granted"),
        "RequestFailed" => T("Ошибка запроса", "Request failed"),
        "ClientRotated" => T("Ключ перевыпущен", "Key rotated"),
        "ClientRevoked" => T("Клиент отозван", "Client revoked"),
        "PolicyAppliedPending" => T("Ожидает подтверждения", "Awaiting confirmation"),
        "PolicyConfirmed" => T("Защита подтверждена", "Protection confirmed"),
        "PolicyRestored" => T("Правила восстановлены", "Rules restored"),
        "PolicyRestoreIncomplete" => T("Откат требует внимания", "Grant revoked"),
        "ClockChanged" => T("Изменилось системное время", "Temporary grants revoked"),
        _ => name ?? T("Событие", "Event")
    };
    private async Task<(string Service, string Protection)> RefreshStatus(CancellationToken token = default)
    {
        // Read service state via the host without waiting on a pipe for an uninstalled service.
        string text;
        try
        {
            text = await Task.Run(() => Native.Run(HostPath(), ["status"], 5000, cancellationToken: token), token);
            token.ThrowIfCancellationRequested();
        }
        catch
        {
            if (!token.IsCancellationRequested && !IsDisposed)
            {
                currentService = null;
                policyConfigured = awaitingConfirmation = hasTrustedSources = null;
                confirmationWindow = null;
                UpdateCountdown();
                RefreshOverviewActions();
                serviceStatus.Text = T("Служба: состояние недоступно", "Service: status unavailable");
                protectionStatus.Text = T("Защита RDP: состояние недоступно", "RDP protection: status unavailable");
                serviceStatus.ForeColor = protectionStatus.ForeColor = StatusColor(Color.SaddleBrown);
            }
            throw;
        }
        using var doc = JsonDocument.Parse(text); var root = doc.RootElement;
        string service = root.GetProperty("service").GetString() ?? "";
        string protection = root.GetProperty("protection").GetString() ?? T("Неизвестно", "Unknown");
        currentService = service;
        serviceStatus.Text = T("Служба: ", "Service: ") + ServiceLabel(service);
        serviceStatus.ForeColor = StatusColor(service == "Running" ? Color.DarkGreen : Color.SaddleBrown);
        protectionStatus.Text = T("Защита RDP: ", "RDP protection: ") + DisplayDetail(protection);
        protectionStatus.ForeColor = StatusColor(protection == "RDP ограничен по IP" ? Color.DarkGreen
            : protection.StartsWith("Защита нарушена", StringComparison.Ordinal) || protection.StartsWith("Откат не завершён", StringComparison.Ordinal) ? Color.DarkRed : Color.SaddleBrown);
        connectionStatus.ForeColor = SystemColors.WindowText;
        var authorizationPort = root.GetProperty("udpPort");
        connectionStatus.Text = T($"Порт авторизации: UDP {authorizationPort} · Обновлено в {DateTime.Now:HH:mm:ss}",
            $"Authorization port: UDP {authorizationPort} · Updated at {DateTime.Now:HH:mm:ss}");
        awaitingConfirmation = root.TryGetProperty("pendingConfirmation", out var pending) && pending.GetBoolean();
        hasTrustedSources = root.TryGetProperty("hasTrustedSources", out var trustedSources) ? trustedSources.GetBoolean() : null;
        confirmationWindow = null;
        if (awaitingConfirmation == true &&
            root.TryGetProperty("rollbackAt", out var rollback) && rollback.TryGetDateTimeOffset(out var deadline))
        {
            var baseline = root.TryGetProperty("serverNow", out var serverTime) && serverTime.TryGetDateTimeOffset(out var now) ? now : DateTimeOffset.UtcNow;
            confirmationWindow = deadline - baseline;
            confirmationSample = System.Diagnostics.Stopwatch.GetTimestamp();
        }
        UpdateCountdown();
        Populate(clients, root.GetProperty("clients"), ref previousClients);
        Populate(leases, root.GetProperty("leases"), ref previousLeases);
        bool locked = root.TryGetProperty("policyConfigured", out var configured) ? configured.GetBoolean() : protection != "Не настроено";
        policyConfigured = locked;
        RefreshOverviewActions();
        RefreshClientActions();
        trusted.ReadOnly = locked;
        port.Enabled = !locked;
        trustedHint.Text = locked ? T("Список используется действующей политикой. Чтобы изменить его, восстановите правила на вкладке «Обзор», затем примените защиту заново.", "The active policy uses this list. To change it, restore the rules on Overview, then apply protection again.") : "";
        if (service == "Не установлена" && protection == "Не настроено")
            connectionStatus.Text += T("\nУстановите службу, задайте белый список и проверьте правила.", "\nInstall the service, set the allowlist, and check the rules.");
        else if (!locked && hasTrustedSources == false)
            connectionStatus.Text += T("\nПеред применением защиты добавьте адрес администратора в белый список на вкладке «Настройки».", "\nAdd an administrator address to the allowlist in Settings before applying protection.");
        return (service, protection);
    }
    private static void Populate(DataGridView grid, JsonElement array, ref string? previous)
    {
        string data = array.GetRawText();
        if (data == previous) return;
        string selectionKey = ReferenceEquals(grid.Columns["id"], null) ? "ruleId" : "id";
        string? selected = grid.SelectedRows.Count == 1 && grid.Columns.Contains(selectionKey)
            ? grid.SelectedRows[0].Cells[selectionKey].Value?.ToString()
            : null;
        var table = new System.Data.DataTable();
        foreach (var item in array.EnumerateArray())
        {
            if (table.Columns.Count == 0) foreach (var p in item.EnumerateObject()) table.Columns.Add(p.Name);
            table.Rows.Add(item.EnumerateObject().Select(p => (object)FormatCell(p)).ToArray());
        }
        grid.DataSource = table;
        previous = data;
        foreach (DataGridViewColumn column in grid.Columns)
        {
            column.Visible = column.Name is not ("id" or "ruleId" or "clientId" or "enabled" or "created");
            column.HeaderText = column.Name switch
            {
                "id" => T("Идентификатор", "ID"),
                "clientId" => T("Клиент", "Client"),
                "clientName" => T("Клиент", "Client"),
                "name" => T("Имя", "Name"),
                "ip" => T("IP-адрес", "IP address"),
                "lastIp" => T("Последний IP", "Last IP"),
                "enabled" => T("Активен", "Active"),
                "active" => T("Активен", "Active"),
                "expires" => T("Действует до", "Valid until"),
                "created" => T("Дата создания", "Created"),
                "lastRequest" => T("Последний запрос", "Last request"),
                "leaseSeconds" => T("Окно доступа", "Access window"),
                "ruleId" => T("Правило", "Rule"),
                "phase" => T("Состояние", "Status"),
                _ => column.Name
            };
        }
        if (grid.Columns["name"] is { } name) name.DisplayIndex = 0;
        if (selected != null && grid.Columns.Contains(selectionKey))
        {
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (row.Cells[selectionKey].Value?.ToString() != selected) continue;
                grid.ClearSelection();
                var visible = grid.Columns.GetFirstColumn(DataGridViewElementStates.Visible);
                if (visible != null) grid.CurrentCell = row.Cells[visible.Index];
                row.Selected = true;
                break;
            }
        }
    }
    private static string FormatCell(JsonProperty property)
    {
        if (property.Name == "phase") return property.Value.GetString() switch { "Committed" => T("Активно", "Active"), "Prepared" => T("Подготовка", "Preparing"), _ => T("Неизвестно", "Unknown") };
        if (property.Name == "leaseSeconds" && property.Value.TryGetInt32(out int seconds))
            return string.Join(" ", new[] { seconds / 3600 > 0 ? T($"{seconds / 3600} ч", $"{seconds / 3600} h") : "", seconds % 3600 / 60 > 0 ? T($"{seconds % 3600 / 60} мин", $"{seconds % 3600 / 60} min") : "", seconds % 60 > 0 ? T($"{seconds % 60} с", $"{seconds % 60} s") : "" }.Where(part => part.Length > 0));
        if (property.Value.ValueKind == JsonValueKind.Null) return "—";
        if (property.Value.ValueKind is JsonValueKind.True or JsonValueKind.False)
            return property.Value.GetBoolean() ? T("Да", "Yes") : T("Нет", "No");
        if (property.Name is "expires" or "created" or "lastRequest" &&
            property.Value.ValueKind == JsonValueKind.String && property.Value.TryGetDateTimeOffset(out var date))
            return date.ToLocalTime().ToString("dd.MM.yyyy HH:mm");
        return property.Value.ToString();
    }
    private async Task CreateClient()
    {
        var current = Json.Read<Config>(await Request("config"));
        using var dialog = new ClientDialog(true, current);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string? path = ChooseScriptPath(dialog.Platform);
        if (path == null) return;
        string id = AccessExport.ParseClientId(await Request("clients-create", dialog.ClientName, dialog.Seconds.ToString(), dialog.Expiry));
        try { await SaveScript(id, dialog.Server, path, dialog.LaunchRdp); }
        catch (Exception e) { throw new IOException(T("Клиент создан, но скрипт не сохранён. Выберите клиента и нажмите «Сохранить скрипт». ", "The client was created, but the script could not be saved. Select the client and choose Save script. ") + e.Message, e); }
        finally { await RefreshData(); }
    }

    private string? ChooseScriptPath(ClientPlatform platform)
    {
        bool mac = platform == ClientPlatform.MacOS;
        using var save = new SaveFileDialog
        {
            Title = mac ? T("Сохранить скрипт для macOS", "Save macOS script") : T("Сохранить скрипт для Windows", "Save Windows script"),
            Filter = mac
                ? T("AppleScript для macOS (*.applescript)|*.applescript", "AppleScript for macOS (*.applescript)|*.applescript")
                : T("Windows — двойной щелчок (*.bat)|*.bat|PowerShell — для администратора (*.ps1)|*.ps1", "Windows double-click script (*.bat)|*.bat|PowerShell for administrators (*.ps1)|*.ps1"),
            FileName = "portGate-Access",
            OverwritePrompt = true,
            AddExtension = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            RestoreDirectory = true
        };
        save.FileOk += (_, e) =>
        {
            string extension = Path.GetExtension(save.FileName).ToLowerInvariant();
            bool valid = mac ? extension == ".applescript" : extension is ".bat" or ".ps1";
            if (valid) return;
            e.Cancel = true;
            MessageBox.Show(this, mac ? T("Укажите расширение .applescript.", "Use the .applescript extension.") : T("Укажите расширение .bat или .ps1.", "Use the .bat or .ps1 extension."),
                T("Формат скрипта", "Script format"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
        };
        return save.ShowDialog(this) == DialogResult.OK ? save.FileName : null;
    }

    private async Task Export(string id)
    {
        using var dialog = new ClientDialog(true, Json.Read<Config>(await Request("config")), exportOnly: true);
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        string? path = ChooseScriptPath(dialog.Platform);
        if (path != null) await SaveScript(id, dialog.Server, path, dialog.LaunchRdp);
    }
    private async Task SaveScript(string id, string server, string path, bool launch)
    {
        await Local("clients", "export", AccessExport.ParseClientId(id), server, path, launch ? "true" : "false");
        if (!File.Exists(path)) throw new IOException(T("Скрипт не был сохранён: ", "The script could not be saved: ") + path);
        message.Text = T("Скрипт сохранён: ", "Script saved: ") + path;
        if (Path.GetExtension(path).Equals(".applescript", StringComparison.OrdinalIgnoreCase))
        {
            MessageBox.Show(this, T($"Скрипт сохранён:\n{path}\n\n{ClientDialog.MacHelp}\n\nФайл содержит персональный ключ доступа.", $"Script saved:\n{path}\n\n{ClientDialog.MacHelp}\n\nThe file contains a personal access key."),
                T("Скрипт для macOS", "macOS script"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        else
        {
            message.Text += T(". Файл содержит персональный ключ доступа.", ". The file contains a personal access key.");
        }
    }
}

internal enum ClientPlatform { Windows, MacOS }

internal sealed class ClientDialog : Form
{
    internal static string MacHelp => T("На Mac откройте .applescript в Редакторе скриптов, затем нажмите «Выполнить». Чтобы получить .scpt, сохраните файл на Mac в формате «Скрипт».", "On the Mac, open the .applescript in Script Editor and select Run. To get a .scpt file, save it on the Mac in Script format.");
    private readonly TextBox name = new() { Width = 340, Text = T("Пользователь", "User") };
    private readonly TextBox server = new() { Width = 340 };
    private readonly DurationInput duration = new(300);
    private readonly CheckBox limited = new() { AutoSize = true, Text = T("Ограничить срок действия ключа", "Set an expiry date for the key") };
    private readonly DateTimePicker expiry = new() { Value = DateTime.Now.AddMonths(1), Format = DateTimePickerFormat.Short };
    private readonly CheckBox launch = new() { AutoSize = true, Text = T("Запустить RDP после авторизации", "Start RDP after authorization") };
    private readonly ComboBox platform = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 340 };
    public string ClientName => name.Text.Trim(); public string Server => server.Text.Trim(); public int Seconds => duration.Seconds;
    public string Expiry => limited.Checked ? new DateTimeOffset(expiry.Value.Date.AddDays(1)).ToUniversalTime().ToString("O") : "";
    public ClientPlatform Platform => platform.SelectedIndex == 1 ? ClientPlatform.MacOS : ClientPlatform.Windows;
    public bool LaunchRdp => Platform == ClientPlatform.Windows && launch.Checked;
    public ClientDialog(bool export, Config config, ClientRecord? existing = null, bool exportOnly = false)
    {
        server.Text = config.ServerAddress; duration.Seconds = existing?.LeaseSeconds ?? config.LeaseSeconds;
        if (existing != null) { name.Text = existing.Name; limited.Checked = existing.Expires != null; if (existing.Expires != null) expiry.Value = existing.Expires.Value.LocalDateTime.Date.AddDays(-1); }
        Text = exportOnly ? T("Сохранить скрипт доступа", "Save access script") : export ? T("Создать клиента доступа", "Create access client") : T("Изменить клиента доступа", "Edit access client");
        ClientSize = new Size(470, export ? (exportOnly ? 330 : 500) : 280);
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(15) };
        platform.Items.AddRange(["Windows", "macOS"]);
        platform.SelectedIndex = 0;
        if (!exportOnly) { panel.Controls.Add(new Label { Text = T("Название клиента", "Client name"), AutoSize = true }); panel.Controls.Add(name); panel.Controls.Add(new Label { Text = T("Окно доступа (можно выбрать часы)", "Access window (you can choose hours)"), AutoSize = true }); panel.Controls.Add(duration); }
        if (export)
        {
            panel.Controls.Add(new Label { Text = T("IP или DNS сервера", "Server IP address or DNS name"), AutoSize = true });
            panel.Controls.Add(server);
            panel.Controls.Add(new Label { Text = T("Платформа скрипта", "Script platform"), AutoSize = true, Margin = new Padding(3, 8, 3, 0) });
            panel.Controls.Add(platform);
            var platformHelp = new Label { AutoSize = true, MaximumSize = new Size(400, 0) };
            panel.Controls.Add(platformHelp);
            panel.Controls.Add(launch);
            void UpdatePlatform()
            {
                bool mac = Platform == ClientPlatform.MacOS;
                launch.Visible = !mac;
                platformHelp.Text = mac ? MacHelp : T("Выберите .bat для запуска двойным щелчком или .ps1 для Windows PowerShell.", "Choose .bat for double-click use or .ps1 for Windows PowerShell.");
            }
            platform.SelectedIndexChanged += (_, _) => UpdatePlatform();
            UpdatePlatform();
        }
        if (!exportOnly)
        {
            panel.Controls.Add(limited);
            panel.Controls.Add(expiry);
            expiry.Enabled = limited.Checked;
            limited.CheckedChanged += (_, _) => expiry.Enabled = limited.Checked;
        }
        var ok = new Button { Text = export ? T("Выбрать файл…", "Choose file…") : T("Сохранить", "Save"), AutoSize = true };
        var cancel = new Button { Text = T("Отмена", "Cancel"), AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => {
            try {
                if (!exportOnly && ClientName.Length is < 1 or > 100) throw new ArgumentException(T("Введите имя клиента длиной от 1 до 100 символов.", "Enter a client name of 1 to 100 characters."));
                if (export) AccessExport.ValidateServer(Server);
                if (!exportOnly && (Seconds < 30 || Seconds > config.MaxLeaseSeconds)) throw new ArgumentException(T("Окно должно быть от 30 секунд до ", "The access window must be between 30 seconds and ") + config.MaxLeaseSeconds / 3600m + T(" ч. Максимум изменяется в настройках.", " hours. You can change the maximum in Settings."));
                DialogResult = DialogResult.OK; Close();
            } catch (ArgumentException e) { MessageBox.Show(this, DisplayDetail(e.Message), T("Проверьте настройки клиента", "Check client settings"), MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        };
        var buttons = new FlowLayoutPanel { AutoSize = true, Margin = new Padding(0, 10, 0, 0) };
        buttons.Controls.AddRange([ok, cancel]);
        panel.Controls.Add(buttons);
        Controls.Add(panel);
        AcceptButton = ok;
        CancelButton = cancel;
    }
}
internal sealed class DurationInput : FlowLayoutPanel
{
    private static readonly int[] Factors = [1, 60, 3600];
    private readonly NumericUpDown value = new() { Minimum = 30, Maximum = Config.LeaseLimitSeconds, Width = 130 };
    private readonly ComboBox unit = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 120 };
    private int selectedUnit;
    private bool synchronizing;
    public event Action? Changed;
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public int Seconds
    {
        get => checked((int)value.Value * Factors[selectedUnit]);
        set => SetDuration(value, value % 3600 == 0 ? 2 : value % 60 == 0 ? 1 : 0);
    }

    private void SetDuration(int seconds, int index)
    {
        synchronizing = true;
        try
        {
            selectedUnit = index;
            unit.SelectedIndex = index;
            value.Minimum = index == 0 ? 30 : 1;
            value.Maximum = Config.LeaseLimitSeconds / Factors[index];
            value.Value = seconds / Factors[index];
        }
        finally { synchronizing = false; }
    }

    public DurationInput(int seconds)
    {
        AutoSize = true; WrapContents = false; unit.Items.AddRange([T("секунд", "seconds"), T("минут", "minutes"), T("часов", "hours")]); Controls.Add(value); Controls.Add(unit);
        unit.SelectedIndexChanged += (_, _) =>
        {
            int next = unit.SelectedIndex;
            if (synchronizing || next < 0) return;
            int current = Seconds;
            if (current % Factors[next] == 0) SetDuration(current, next);
            else
            {
                SetDuration(current, selectedUnit);
                MessageBox.Show(FindForm(), T("Текущий срок нельзя точно выразить в выбранных единицах. Измените значение в текущих единицах или оставьте его прежним.", "The current duration cannot be expressed exactly in the selected unit. Keep it as is or change the value in the current unit."),
                    T("Длительность доступа", "Access duration"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
        };
        value.ValueChanged += (_, _) => { if (!synchronizing) Changed?.Invoke(); };
        Seconds = seconds;
    }
}
