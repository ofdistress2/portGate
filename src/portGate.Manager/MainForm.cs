using System.Text.Json;
using portGate.Core;
using static portGate.Manager.PanelLanguage;

namespace portGate.Manager;
internal sealed partial class MainForm : Form
{
    private readonly Label serviceStatus = new() { AutoSize = true, Text = T("Служба: получение состояния…", "Service: checking status…") };
    private readonly Label protectionStatus = new() { AutoSize = true, Text = T("Защита: получение состояния…", "Protection: checking status…"), MaximumSize = new Size(700, 0) };
    private readonly Label connectionStatus = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private readonly Label confirmation = new() { AutoSize = true, Visible = false, Margin = new Padding(0, 0, 0, 3) };
    private readonly StatusLabel operationTitle = new(T("Последнее действие", "Latest action"));
    private readonly Label operationDetail = new() { AutoSize = true, Anchor = AnchorStyles.Left, Text = T("Действий пока не выполняли.", "No actions yet.") };
    private readonly Dictionary<Button, Func<bool>> overviewActions = [];
    private readonly List<Button> clientActions = [];
    private readonly ToolTip actionHints = new();
    private Button revokeClient = null!;
    private string? currentService;
    private bool? policyConfigured;
    private bool? awaitingConfirmation;
    private bool? hasTrustedSources;
    private TimeSpan? confirmationWindow;
    private long confirmationSample;
    private enum Notice { Working, Success, Attention, Error, Cancelled }
    private readonly ToolStripStatusLabel message = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly DataGridView clients = GridStyler.Create();
    private readonly DataGridView leases = GridStyler.Create();
    private readonly Label journalStatus = new() { AutoSize = true, Text = T("Журнал ещё не загружен.", "The journal has not been loaded.") };
    private readonly DataGridView events = GridStyler.Create();
    private readonly Label planSummary = new() { AutoSize = true, Text = T("Нажмите «Проверить правила», чтобы увидеть результат.", "Select Check rules to see the result.") };
    private FirewallPlan? latestPlan;
    private readonly NumericUpDown port = Number(1024, 65535, 51888);
    private readonly DurationInput duration = new(300);
    private readonly DurationInput maximumDuration = new(86400);
    private readonly TextBox serverAddress = new() { Width = 650 };
    private readonly TextBox trusted = new() { Multiline = true, Height = 76, ScrollBars = ScrollBars.Vertical };
    private readonly Label trustedHint = new() { AutoSize = true, MaximumSize = new Size(700, 0) };
    private Config? config;
    private string? previousClients, previousLeases, selectedClientId;
    private JsonElement clientSnapshot;
    private bool bindingClients;
    private long serverTimeSample;
    private DateTimeOffset sampledServerTime;
    private readonly Dictionary<string, DateTimeOffset> leaseExpiries = [];
    private readonly List<(string Time, string Kind, string Detail)> journalEntries = [];
    private bool busy;
    private CancellationTokenSource? backgroundRefresh;
    private bool settingsDirty, loadingSettings;
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 15000 };
    private readonly System.Windows.Forms.Timer countdown = new() { Interval = 1000 };
    internal bool LanguageChanged { get; private set; }

    public MainForm(bool showSettings = false)
    {
        Text = "portGate " + VersionLabel + T(" — управление доступом RDP", " — RDP access management");
        MinimumSize = new Size(940, 660);
        Size = new Size(1140, 760);
        Font = Theme.Body;
        trusted.Font = Theme.Mono;
        trusted.WordWrap = false;
        BackColor = Theme.Canvas;
        ForeColor = Theme.Text;
        AutoScaleDimensions = new SizeF(96, 96);
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterScreen;

        var pages = BuildShell();
        var overview = pages[0];
        var warning = new CardPanel { BackColor = Theme.Pick(0xFEF3C7, SystemColors.Window), Visible = false, Padding = new Padding(11) };
        confirmationBanner = warning;
        var warningBody = AddStack(warning);
        var timerRow = Row(warningBody);
        confirmation.Font = Theme.CardTitle;
        confirmation.Visible = true;
        timerRow.Controls.AddRange([confirmation, confirmationProgress]);
        var confirmationActions = Row(warningBody);
        AddRow(overview, warning);
        var welcome = new CardPanel { BackColor = Theme.AccentSoft, Padding = new Padding(11), Visible = false };
        setupBanner = welcome;
        var welcomeBody = AddStack(welcome);
        welcomeBody.Controls.Add(Copy(T("1. Установите службу → 2. Задайте белый список → 3. Примените защиту",
            "1. Install the service → 2. Set the allowlist → 3. Apply protection")));
        Button(Row(welcomeBody), T("Открыть настройки", "Open settings"), () => SelectPage(2), ActionStyle.Primary);
        AddRow(overview, welcome);
        var cards = TwoColumns();
        var serviceCard = new CardPanel { Dock = DockStyle.Top, Padding = new Padding(11), Margin = new Padding(0, 0, 7, 0) };
        cards.Controls.Add(serviceCard, 0, 0);
        var serviceBody = AddStack(serviceCard);
        var serviceHeading = Row(serviceBody);
        Heading(serviceHeading, T("Служба", "Service"));
        serviceHeading.Controls.Add(serviceCardStatus);
        var service = Row(serviceBody);
        var policyCard = new CardPanel { Dock = DockStyle.Top, Padding = new Padding(11), Margin = new Padding(7, 0, 0, 0) };
        cards.Controls.Add(policyCard, 1, 0);
        var policyBody = AddStack(policyCard);
        var policyHeading = Row(policyBody);
        Heading(policyHeading, T("Защита RDP", "RDP protection"));
        policyHeading.Controls.Add(policyCardStatus);
        var policy = Row(policyBody);
        AddRow(overview, cards);
        foreach (var (caption, title, command, expectedState, success) in new[]
        {
            (T("Установить/Обновить", "Install / Upgrade"), T("Установка службы", "Install service"), "install", "Installed", T("Служба установлена. Запустите её кнопкой «Запустить».", "Service installed. Select Start to run it.")),
            (T("Запустить", "Start"), T("Запуск службы", "Start service"), "start", "Running", T("Служба запущена.", "The service is running.")),
            (T("Остановить", "Stop"), T("Остановка службы", "Stop service"), "stop", "Stopped", T("Служба остановлена.", "The service has stopped.")),
            (T("Перезапустить", "Restart"), T("Перезапуск службы", "Restart service"), "restart", "Running", T("Служба перезапущена.", "The service restarted."))
        })
            OverviewButton(service, caption, title, async () =>
            {
                await Local(command);
                return await VerifyServiceState(expectedState, success);
            }, style: command == "install" ? ActionStyle.Ghost : ActionStyle.Secondary, refresh: false, available: () => currentService switch
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
        }, refresh: false, available: () => currentService is null or "Stopped" or "Running" or "Paused", style: ActionStyle.DangerOutline);
        OverviewButton(policy, T("Проверить", "Check rules"), T("Проверка правил", "Check firewall rules"), async () =>
        {
            var p = await ReadPlan();
            if (!p.Safe) return (Notice.Attention, T($"Найдено конфликтов: {p.Conflicts.Count}. Откройте подробности плана.", $"Found {p.Conflicts.Count} conflicts. Open the plan details for more information."));
            return (p.Warnings.Count > 0 ? Notice.Attention : Notice.Success, T($"Конфликтов нет. Правил к отключению: {p.Disable.Count}. Предупреждений: {p.Warnings.Count}.", $"No conflicts. Rules to disable: {p.Disable.Count}. Warnings: {p.Warnings.Count}."));
        });
        OverviewButton(policy, T("Применить…", "Apply protection…"), T("Применение защиты", "Apply protection"), async () =>
        {
            var p = await ReadPlan();
            if (!p.Safe) return (Notice.Error, T($"Применение остановлено. {DisplayDetail(p.Conflicts[0])}", $"Unable to apply protection. {DisplayDetail(p.Conflicts[0])}"));
            if (!ShowPlan(p, confirmApply: true))
                return (Notice.Cancelled, T("Применение отменено.", "Applying protection was cancelled."));
            return (Notice.Attention, await Request("apply"));
        }, style: ActionStyle.Primary, available: () => currentService != "Не установлена" && policyConfigured != true && hasTrustedSources != false);
        OverviewButton(confirmationActions, T("Подтвердить новый вход", "Confirm new sign-in"), T("Подтверждение нового входа", "Confirm new RDP sign-in"),
            async () => (Notice.Success, await Request("confirm")), style: ActionStyle.Primary, available: () => awaitingConfirmation == true && ConfirmationRemaining() is { Ticks: > 0 });
        async Task<(Notice, string)> RestoreRules()
        {
            if (!Confirm(T("Восстановить правила, изменённые portGate?", "Restore the rules changed by portGate?")))
                return (Notice.Cancelled, T("Восстановление отменено.", "Restore cancelled."));
            return (Notice.Success, await Request("restore"));
        }
        OverviewButton(policy, T("Восстановить…", "Restore rules…"),
            T("Восстановление правил", "Restore firewall rules"), RestoreRules,
            style: ActionStyle.DangerOutline, available: () => policyConfigured != false);
        OverviewButton(confirmationActions, T("Восстановить правила…", "Restore rules…"),
            T("Восстановление правил", "Restore firewall rules"), RestoreRules,
            style: ActionStyle.DangerOutline, available: () => policyConfigured != false);
        var planDetails = Button(policy, T("План…", "Plan details…"), () =>
        {
            if (latestPlan is { } snapshot) ShowPlan(snapshot, confirmApply: false);
            return Task.CompletedTask;
        }, ActionStyle.Ghost);
        overviewActions.Add(planDetails, () => latestPlan != null);
        policyBody.Controls.Add(planSummary);
        serviceCard.Dock = policyCard.Dock = DockStyle.Fill;
        var operationCard = new CardPanel { AutoSize = true, Padding = new Padding(10, 6, 10, 6) };
        var operation = new TableLayoutPanel
        {
            Dock = DockStyle.Top, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2, RowCount = 1, Margin = Padding.Empty
        };
        operation.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42));
        operation.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58));
        operationTitle.Font = Theme.CardTitle;
        operationTitle.Anchor = AnchorStyles.Left;
        operation.Controls.Add(operationTitle, 0, 0);
        operation.Controls.Add(operationDetail, 1, 0);
        operation.SizeChanged += (_, _) =>
        {
            int width = operation.ClientSize.Width;
            int titleWidth = width * 42 / 100;
            operationTitle.MaximumSize = new Size(Math.Max(1, titleWidth - operationTitle.Margin.Horizontal), 0);
            operationDetail.MaximumSize = new Size(Math.Max(1, width - titleWidth - operationDetail.Margin.Horizontal), 0);
        };
        operationCard.Controls.Add(operation);
        AddRow(overview, operationCard);
        var grants = GridCard(leases);
        var grantsHeading = AddStack(grants);
        var leaseActions = Row(grantsHeading);
        leaseActions.Controls.Add(leaseCount);
        grantsHeading.Controls.Add(Copy(T("Отзыв разрешения оставляет открытый RDP-сеанс активным.",
            "Revoking a grant leaves existing RDP sessions open.")));
        AddRow(overview, grants, fill: true);
        OverviewButton(leaseActions, T("Отозвать выбранное…", "Revoke selected…"), T("Отзыв разрешения", "Revoke grant"), async () =>
        {
            string id = SelectedKey(leases, "ruleId") ?? throw new InvalidOperationException(T("Выберите разрешение.", "Select a grant."));
            if (!Confirm(T("Отозвать выбранное разрешение? Ключ останется действующим, клиент сможет запросить доступ заново.", "Revoke the selected grant? The key stays valid and the client can request access again.")))
                return (Notice.Cancelled, T("Отзыв отменён.", "Revocation cancelled."));
            return (Notice.Success, await Request("lease-revoke", id));
        }, style: ActionStyle.DangerOutline, available: () => SelectedKey(leases, "ruleId") != null);
        OverviewButton(leaseActions, T("Отозвать все", "Revoke all"), T("Отзыв временных разрешений", "Revoke temporary grants"),
            async () => (Notice.Success, await Request("leases-revoke")), style: ActionStyle.DangerOutline, available: () => leases.Rows.Count > 0);
        leases.SelectionChanged += (_, _) => RefreshOverviewActions();
        var access = pages[1];
        AddRow(access, FilterBar(clientSearch, clientFilter,
            T("Поиск по имени или IP", "Search by name or IP"), [T("Все", "All"), T("Активные", "Active"), T("Отозванные", "Revoked")]));
        AddRow(access, GridCard(clients), fill: true);
        var clientActionsCard = new CardPanel { Padding = new Padding(10, 5, 10, 5) };
        var clientActionsBody = AddStack(clientActionsCard);
        clientActionsBody.Controls.Add(selectedClient);
        var tools = Row(clientActionsBody);
        AddRow(access, clientActionsCard);
        clientActions.Add(Button(tools, T("Сохранить скрипт…", "Save script…"), async () => await Export(SelectedId())));
        revokeClient = Button(tools, T("Отозвать", "Revoke"), async () => { if (Confirm(T("Отозвать доступ и временные разрешения клиента?", "Revoke the client's access and temporary grants?"))) { message.Text = DisplayDetail(await Request("clients-revoke", SelectedId())); await RefreshData(); } }, ActionStyle.DangerOutline);
        clientActions.Add(Button(tools, T("Удалить ключ…", "Delete key…"), async () =>
        {
            string id = SelectedId();
            string? name = clients.SelectedRows[0].Cells["name"].Value?.ToString();
            if (!Confirm(T($"Окончательно удалить ключ клиента «{name}»? Его временные разрешения будут отозваны, а сохранённые скрипты перестанут работать.",
                $"Permanently delete the key for “{name}”? Its temporary grants will be revoked and saved scripts will stop working."))) return;
            message.Text = DisplayDetail(await Request("clients-delete", id));
            selectedClientId = null;
            await RefreshData();
        }, ActionStyle.DangerOutline));
        clientActions.Add(Button(tools, T("Перевыпустить ключ", "Rotate key"), async () => { if (Confirm(T("Старые скрипты перестанут работать. Перевыпустить ключ?", "Existing scripts will stop working. Rotate the key?"))) { message.Text = DisplayDetail(await Request("clients-rotate", SelectedId())); await RefreshData(); } }));
        clientActions.Add(Button(tools, T("Изменить имя и срок…", "Edit name and duration…"), async () =>
        {
            string id = SelectedId();
            var existing = Json.Read<List<ClientRecord>>(await Request("clients-list")).Single(c => c.Id == id);
            using var dialog = new ClientDialog(false, Json.Read<Config>(await Request("config")), existing);
            if (dialog.ShowDialog(this) != DialogResult.OK) return;
            message.Text = DisplayDetail(await Request("clients-edit", id, dialog.ClientName, dialog.Expiry, dialog.Seconds.ToString())); await RefreshData();
        }));
        clients.SelectionChanged += (_, _) =>
        {
            if (bindingClients) return;
            selectedClientId = SelectedKey(clients, "id") ?? selectedClientId;
            RefreshClientActions();
        };
        clientSearch.TextChanged += (_, _) => FilterClients();
        clientFilter.SelectedIndexChanged += (_, _) => FilterClients();
        GridStyler.PaintPills(clients, "active", row => clients.Rows[row].Cells["active"].Value?.ToString() switch
        {
            var status when status == T("Активен", "Active") => PillTone.Good,
            var status when status == T("Истёк", "Expired") => PillTone.Warning,
            _ => PillTone.Neutral
        });
        GridStyler.PaintPills(leases, "phase", row => leases.Rows[row].Cells["phase"].Value?.ToString() ==
            T("Активно", "Active") ? PillTone.Good : PillTone.Warning);

        var settings = pages[2];
        var settingsScroll = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Margin = new Padding(0) };
        var settingsGrid = TwoColumns();
        settingsScroll.Controls.Add(settingsGrid);
        AddRow(settings, settingsScroll, fill: true);
        var network = SettingsCard(settingsGrid, 0, 0, T("Сервер и сеть", "Server and network"));
        Field(network, T("Внешний IP или DNS", "Public IP or DNS name"), serverAddress);
        Field(network, T("Порт UDP авторизации", "UDP authorization port"), port);
        network.Controls.Add(portLock);
        var windows = SettingsCard(settingsGrid, 1, 0, T("Окна доступа", "Access windows"));
        Field(windows, T("Окно доступа по умолчанию", "Default access window"), duration);
        Field(windows, T("Максимальное окно доступа", "Maximum access window"), maximumDuration);
        var allowlist = SettingsCard(settingsGrid, 0, 1, T("Постоянный белый список RDP", "Permanent RDP allowlist"), 2);
        var editJson = Button(Row(allowlist), T("Расширенные настройки (JSON)…", "Advanced settings (JSON)…"), EditJsonConfig);
        actions[editJson] = () => hasTrustedSources.HasValue;
        Field(allowlist, T("IP или CIDR, по одному на строку", "One IP address or CIDR per line"), trusted);
        allowlist.Controls.Add(trustedHint);
        var languageBody = SettingsCard(settingsGrid, 0, 2, T("Интерфейс", "Interface"), 2);
        var languageRow = Row(languageBody);
        languageRow.Controls.Add(Copy(T("Язык интерфейса", "Interface language")));
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
        var applyLanguage = new ActionButton()
        {
            Name = "applyLanguage",
            Text = T("Применить язык", "Apply language"),
            AutoSize = true,
            Enabled = false
        };
        languageRow.Controls.Add(applyLanguage);
        actions.Add(applyLanguage, () => SelectedLanguage() != Current);
        languages.SelectedIndexChanged += (_, _) => RefreshOverviewActions();
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

        var footer = new CardPanel { Padding = new Padding(10, 5, 10, 5) };
        var settingsActions = Row(AddStack(footer));
        settingsActions.Controls.Add(settingsStatus);
        AddRow(settings, footer);
        var saveSettings = Button(settingsActions, T("Сохранить настройки", "Save settings"), async () =>
        {
            config ??= Json.Read<Config>(await Request("config"));
            var next = Json.Read<Config>(Json.Write(config));
            next.UdpPort = (int)port.Value; next.LeaseSeconds = duration.Seconds; next.MaxLeaseSeconds = maximumDuration.Seconds;
            next.ServerAddress = serverAddress.Text.Trim();
            next.TrustedRdpCidrs = trusted.Lines.Select(x => x.Trim()).Where(x => x != "").ToArray();
            next.Validate();
            message.Text = DisplayDetail(await Request("config-save", Json.Write(next)));
            SetSettingsDirty(false); await RefreshData();
        }, ActionStyle.Primary);
        actions[saveSettings] = () => hasTrustedSources.HasValue && settingsDirty && allowlistEditable;
        var discardSettings = Button(settingsActions, T("Отменить изменения", "Discard changes"), async () =>
        {
            if (!settingsDirty || !Confirm(T("Загрузить сохранённые настройки и отбросить изменения формы?", "Reload saved settings and discard changes on this form?"))) return;
            SetSettingsDirty(false);
            await RefreshData();
        });
        actions[discardSettings] = () => settingsDirty;
        void Dirty() { if (!loadingSettings) SetSettingsDirty(true); }
        serverAddress.TextChanged += (_, _) => Dirty(); trusted.TextChanged += (_, _) => Dirty(); port.ValueChanged += (_, _) => Dirty();
        port.TextChanged += (_, _) => Dirty();
        duration.Changed += Dirty; maximumDuration.Changed += Dirty;
        var journal = pages[3];
        AddRow(journal, FilterBar(journalSearch, journalFilter, T("Поиск по тексту", "Search events"),
            [T("Все", "All"), T("Доступ", "Access"), T("Политика", "Policy"), T("Ошибки", "Errors")]));
        AddRow(journal, journalStatus);
        events.DefaultCellStyle.WrapMode = DataGridViewTriState.True;
        events.AutoSizeRowsMode = DataGridViewAutoSizeRowsMode.DisplayedCellsExceptHeaders;
        GridStyler.PaintPills(events, "event", row => JournalCategory(events.Rows[row].Cells["kind"].Value?.ToString()) switch
        {
            1 => PillTone.Good, 2 => PillTone.Warning, 3 => PillTone.Error, _ => PillTone.Neutral
        });
        AddRow(journal, GridCard(events), fill: true);
        journalSearch.TextChanged += (_, _) => FilterJournal();
        journalFilter.SelectedIndexChanged += (_, _) => FilterJournal();
        Populate(clients, [], "id", null);
        Populate(leases, [], "ruleId", null);
        SetSettingsDirty(false);
        Shown += async (_, _) =>
        {
            await SelectPage(showSettings ? 2 : 0, refresh: false);
            await Guard(RefreshData);
        };
        timer.Tick += async (_, _) => await RefreshInBackground();
        timer.Start();
        countdown.Tick += (_, _) => UpdateCountdown();
        countdown.Start();
        RefreshSettingsAvailability();
        RefreshOverviewActions();
        RefreshClientActions();
        FormClosing += (_, e) => { if (settingsDirty && !Confirm(T("Закрыть окно без сохранения настроек?", "Close the window without saving your settings?"))) e.Cancel = true; };
        FormClosed += (_, _) => { timer.Dispose(); countdown.Dispose(); actionHints.Dispose(); backgroundRefresh?.Cancel(); };
    }
    private static NumericUpDown Number(int min, int max, int value) => new() { Minimum = min, Maximum = max, Value = value, Width = 150 };
    private Button Button(Control parent, string text, Func<Task> action, ActionStyle style = ActionStyle.Secondary)
    {
        var button = new ActionButton(style) { Text = text };
        actions.Add(button, () => true);
        button.Click += async (_, _) => { if (!busy) await Guard(action); }; parent.Controls.Add(button);
        return button;
    }
    private void OverviewButton(Control parent, string caption, string title, Func<Task<(Notice State, string Detail)>> action, bool refresh = true, Func<bool>? available = null, ActionStyle style = ActionStyle.Secondary)
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
        }, style);
        overviewActions.Add(button, available ?? (() => true));
    }
    private void RefreshOverviewActions()
    {
        foreach (var (button, isAvailable) in actions)
            button.Enabled = !busy && isAvailable();
        foreach (var (button, isAvailable) in overviewActions)
            button.Enabled = !busy && isAvailable();
        RefreshClientActions();
    }
    private void RefreshClientActions()
    {
        string? id = SelectedKey(clients, "id");
        bool selected = !busy && id != null;
        selectedClient.Text = id == null ? T("Выберите клиента", "Select a client") :
            T("Выбран: ", "Selected: ") + clients.SelectedRows[0].Cells["name"].Value;
        foreach (var button in clientActions) button.Enabled = selected;
        bool enabledClient = selected && clients.Columns.Contains("enabled") &&
            clients.SelectedRows[0].Cells["enabled"].Value is true;
        if (revokeClient != null) revokeClient.Enabled = enabledClient;
    }
    private TimeSpan? ConfirmationRemaining() => confirmationWindow - System.Diagnostics.Stopwatch.GetElapsedTime(confirmationSample);
    private void UpdateCountdown()
    {
        bool visible = awaitingConfirmation == true && ConfirmationRemaining().HasValue;
        confirmationBanner.Visible = visible;
        confirmationProgress.Value = Math.Clamp((int)Math.Ceiling(ConfirmationRemaining()?.TotalSeconds ?? 0), 0, 120);
        UpdateLeaseTimers();
        if (!visible) return;
        var remaining = ConfirmationRemaining()!.Value;
        confirmation.ForeColor = StatusColor(remaining.TotalSeconds <= 30 ? Color.DarkRed : Color.SaddleBrown);
        if (remaining > TimeSpan.Zero)
        {
            int seconds = (int)Math.Ceiling(remaining.TotalSeconds);
            confirmation.Text = T($"Подтвердите вход из нового RDP-сеанса · {seconds / 60:00}:{seconds % 60:00}",
                $"Confirm from a new RDP session · {seconds / 60:00}:{seconds % 60:00}");

        }
        else
        {
            confirmation.Text = T("Время подтверждения истекло. Ожидается обновление состояния правил.", "The confirmation window expired. Waiting for firewall status to refresh.");

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
        operationTitle.Text = $"{label} · {title} · {DateTime.Now:HH:mm:ss}";
        operationDetail.Text = DisplayDetail(detail).ReplaceLineEndings(" ");
        if (operationDetail.Text.Length > 170) operationDetail.Text = operationDetail.Text[..167] + "…";
        operationTitle.SetTone(state switch
        {
            Notice.Success => PillTone.Good,
            Notice.Attention => PillTone.Warning,
            Notice.Error => PillTone.Error,
            _ => PillTone.Neutral
        });
    }
    private static Color StatusColor(Color color) => Theme.Pick(color.ToArgb() & 0xffffff, SystemColors.WindowText);
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
        using var dialog = new PlanDialog(snapshot, confirmApply);
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
        string path = Path.Combine(AppContext.BaseDirectory, Deployment.HostName);
        bool runningFromInstalledDirectory = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory)
            .Equals(Path.GetDirectoryName(Deployment.InstalledHost), StringComparison.OrdinalIgnoreCase);
        if ((!installing || runningFromInstalledDirectory) && File.Exists(Deployment.InstalledHost))
            return Deployment.InstalledHost;
        if (!File.Exists(path)) throw new FileNotFoundException(T("portgate.Host.exe должен находиться рядом с панелью. Используйте папку опубликованной поставки.", "portgate.Host.exe must be available next to the panel. Use the folder from the release archive."));
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
            string temp = Path.Combine(Path.GetTempPath(), "portgate-" + Guid.NewGuid().ToString("N") + ".json");
            try { File.WriteAllText(temp, args[0]); return await Local(command, temp); } finally { File.Delete(temp); }
        }
        return await Local(command, args);
    }
    private async Task RefreshData()
    {
        var (service, protection) = await RefreshStatus();
        if (service == "Не установлена" && protection == "Не настроено" && hasTrustedSources == null) return;
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
        using var dialog = new JsonConfigDialog(json, !allowlistEditable, async next =>
        {
            message.Text = DisplayDetail(await Request("config-save", Json.Write(next)));
        });
        if (dialog.ShowDialog(this) == DialogResult.OK) await RefreshData();
    }
    private async Task RefreshJournal()
    {
        string output = await Local("events");
        journalEntries.Clear();
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
                journalEntries.Add((DateTimeOffset.TryParse(date, out var time) ? time.ToLocalTime().ToString("dd.MM.yyyy HH:mm:ss") : date ?? "",
                    kind ?? "", detail is null ? "" : DisplayDetail(detail)));
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
            {
                journalEntries.Add(("", "UnreadableEntry", line));
            }
        }
        FilterJournal();
    }

    private async Task ClearJournal()
    {
        if (!Confirm(T("Удалить все записи журнала, включая архивные? Это действие необратимо.",
            "Delete all journal entries, including archived entries? This action is permanent."))) return;
        message.Text = DisplayDetail(await Request("events-clear"));
        await RefreshJournal();
    }

    private void FilterJournal()
    {
        var table = new System.Data.DataTable();
        foreach (string name in new[] { "time", "event", "detail", "kind" }) table.Columns.Add(name);
        string query = journalSearch.Text.Trim();
        foreach (var (time, kind, detail) in journalEntries)
        {
            if (journalFilter.SelectedIndex > 0 && journalFilter.SelectedIndex != JournalCategory(kind)) continue;
            string caption = JournalEvent(kind);
            if (query.Length > 0 && !Contains(time, query) && !Contains(caption, query) && !Contains(detail, query)) continue;
            table.Rows.Add(time, caption, detail, kind);
        }
        events.DataSource = table;
        foreach (DataGridViewColumn column in events.Columns)
        {
            (column.HeaderText, column.FillWeight) = column.Name switch
            {
                "time" => (T("Время", "Time"), 90),
                "event" => (T("Событие", "Event"), 110),
                "detail" => (T("Подробности", "Details"), 200),
                _ => (column.Name, 100)
            };
            column.Visible = column.Name != "kind";
            if (column.Name is "time" or "detail") column.DefaultCellStyle.Font = Theme.Mono;
        }
        journalStatus.Text = table.Rows.Count == 0 ? T("Записей нет.", "No entries.") :
            T($"Записей: {table.Rows.Count}. Сначала показаны новые.", $"{table.Rows.Count} entries. Newest first.");
    }

    private static int JournalCategory(string? name) => name switch
    {
        "AccessGranted" or "LeaseRevoked" or "ClientRotated" or "ClientRevoked" or "ClientDeleted" => 1,
        "PolicyAppliedPending" or "PolicyConfirmed" or "PolicyRestored" or "AllowlistUpdated" or "ClockChanged" => 2,
        "ServiceFailed" or "RequestFailed" or "PolicyRestoreIncomplete" or "AllowlistRollbackIncomplete" or "AllowlistHealthCheckFailed" or "UnreadableEntry" => 3,
        _ => 0
    };
    private static string JournalEvent(string? name) => name switch
    {
        "ServiceStarted" => T("Служба запущена", "Service started"),
        "ServiceStopped" => T("Служба остановлена", "Service stopped"),
        "ServiceFailed" => T("Ошибка службы", "Service error"),
        "AccessGranted" => T("Доступ выдан", "Access granted"),
        "RequestFailed" => T("Ошибка запроса", "Request failed"),
        "ClientRotated" => T("Ключ перевыпущен", "Key rotated"),
        "ClientRevoked" => T("Клиент отозван", "Client revoked"),
        "ClientDeleted" => T("Ключ удалён", "Key deleted"),
        "PolicyAppliedPending" => T("Ожидает подтверждения", "Awaiting confirmation"),
        "PolicyConfirmed" => T("Защита подтверждена", "Protection confirmed"),
        "AllowlistUpdated" => T("Белый список обновлён", "Allowlist updated"),
        "AllowlistRollbackIncomplete" => T("Сбой отката белого списка", "Allowlist rollback failed"),
        "AllowlistHealthCheckFailed" => T("Ошибка проверки белого списка", "Allowlist health check failed"),
        "UnreadableEntry" => T("Не удалось прочитать запись", "Could not read entry"),
        "PolicyRestored" => T("Правила восстановлены", "Rules restored"),
        "PolicyRestoreIncomplete" => T("Откат требует внимания", "Rollback requires attention"),
        "ClockChanged" => T("Изменилось системное время", "System clock changed"),
        "LeaseRevoked" => T("Разрешение отозвано", "Grant revoked"),
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
                RefreshSettingsAvailability();
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
        serviceStatus.Text = T("● Служба: ", "● Service: ") + ServiceLabel(service);
        serviceStatus.ForeColor = StatusColor(service == "Running" ? Color.DarkGreen : Color.SaddleBrown);
        protectionStatus.Text = T("● Защита: ", "● Protection: ") + DisplayDetail(protection);
        protectionStatus.ForeColor = StatusColor(protection == "RDP ограничен по IP" ? Color.DarkGreen
            : protection.StartsWith("Защита нарушена", StringComparison.Ordinal) || protection.StartsWith("Откат не завершён", StringComparison.Ordinal) ? Color.DarkRed : Color.SaddleBrown);
        connectionStatus.ForeColor = Theme.Muted;
        var authorizationPort = root.GetProperty("udpPort");
        connectionStatus.Text = $"UDP {authorizationPort} · {DateTime.Now:HH:mm:ss}";
        serviceCardStatus.Text = $"● {ServiceLabel(service)} · UDP {authorizationPort}";
        serviceCardStatus.SetTone(service == "Running" ? PillTone.Good : PillTone.Warning);
        string rdpPort = root.TryGetProperty("rdpPort", out var rdp) && rdp.ValueKind == JsonValueKind.Number
            ? rdp.GetInt32().ToString() : "—";
        bool protectionFailed = protection.StartsWith("Защита нарушена", StringComparison.Ordinal) ||
            protection.StartsWith("Откат не завершён", StringComparison.Ordinal);
        string protectionCaption = protectionFailed ? T("Требуется внимание", "Needs attention") :
            protection == "RDP ограничен по IP" ? T("Активна", "Active") :
            DisplayDetail(protection.Split('\n')[0]);
        policyCardStatus.Text = $"● {protectionCaption} · RDP {rdpPort}";
        policyCardStatus.SetTone(protectionFailed ? PillTone.Error :
            protection == "RDP ограничен по IP" ? PillTone.Good : PillTone.Warning);
        awaitingConfirmation = root.TryGetProperty("pendingConfirmation", out var pending) && pending.GetBoolean();
        hasTrustedSources = root.TryGetProperty("hasTrustedSources", out var trustedSources) ? trustedSources.GetBoolean() : null;
        sampledServerTime = root.TryGetProperty("serverNow", out var serverTime) && serverTime.TryGetDateTimeOffset(out var now) ? now : DateTimeOffset.UtcNow;
        serverTimeSample = System.Diagnostics.Stopwatch.GetTimestamp();
        confirmationWindow = null;
        if (awaitingConfirmation == true &&
            root.TryGetProperty("rollbackAt", out var rollback) && rollback.TryGetDateTimeOffset(out var deadline))
        {
            confirmationWindow = deadline - sampledServerTime;
            confirmationSample = serverTimeSample;
        }
        var currentClients = root.GetProperty("clients");
        navigation[1].Nav.SetCount(currentClients.EnumerateArray().Count(client => client.GetProperty("active").GetBoolean()));
        if (clientSnapshot.ValueKind != JsonValueKind.Array || clientSnapshot.GetRawText() != currentClients.GetRawText())
        {
            clientSnapshot = currentClients.Clone();
            FilterClients();
        }
        var currentLeases = root.GetProperty("leases");
        if (previousLeases != currentLeases.GetRawText())
        {
            leaseExpiries.Clear();
            foreach (var lease in currentLeases.EnumerateArray())
                if (lease.GetProperty("expires").TryGetDateTimeOffset(out var expiry))
                    leaseExpiries.Add(lease.GetProperty("ruleId").GetString()!, expiry);
            Populate(leases, currentLeases.EnumerateArray(), "ruleId", SelectedKey(leases, "ruleId"));
            previousLeases = currentLeases.GetRawText();
        }
        bool locked = root.TryGetProperty("policyConfigured", out var configured) ? configured.GetBoolean() : protection != "Не настроено";
        policyConfigured = locked;
        allowlistEditable = root.TryGetProperty("allowlistEditable", out var editable) ? editable.GetBoolean() : !locked;
        RefreshSettingsAvailability();
        setupBanner.Visible = awaitingConfirmation != true && (service == "Не установлена" || !locked && hasTrustedSources == false);
        UpdateCountdown();
        RefreshOverviewActions();
        RefreshClientActions();
        return (service, protection);
    }

    private void RefreshSettingsAvailability()
    {
        bool initialized = hasTrustedSources.HasValue;
        bool locked = policyConfigured == true;
        serverAddress.Enabled = duration.Enabled = maximumDuration.Enabled = trusted.Enabled = initialized;
        trusted.ReadOnly = !allowlistEditable;
        port.Enabled = initialized && !locked;
        portLock.Visible = initialized && locked;
        trustedHint.Text = !initialized
            ? currentService == "Не установлена"
                ? T("Сначала установите службу на вкладке «Обзор».", "Install the service on Overview first.")
                : T("Ожидается состояние службы.", "Waiting for service status.")
            : !allowlistEditable
            ? T("Редактирование доступно после подтверждения защиты или завершения восстановления.", "Editing becomes available after protection is confirmed or restoration finishes.")
            : locked
                ? T("Список применяется сразу, без перезапуска службы. Укажите хотя бы один IP или CIDR.", "Changes apply immediately without restarting the service. Keep at least one IP address or CIDR.")
                : T("Перед применением защиты укажите адрес, с которого администратор подключится по RDP.", "Before applying protection, enter the address the administrator will use to connect over RDP.");
    }
    private void FilterClients()
    {
        if (clientSnapshot.ValueKind != JsonValueKind.Array) return;
        string query = clientSearch.Text.Trim();
        int filter = clientFilter.SelectedIndex;
        var entries = clientSnapshot.EnumerateArray().Where(client =>
            (filter != 1 || client.GetProperty("active").GetBoolean()) &&
            (filter != 2 || !client.GetProperty("enabled").GetBoolean()) &&
            (query.Length == 0 || Contains(client.GetProperty("name").GetString(), query) ||
                Contains(client.GetProperty("lastIp").GetString(), query)));
        string data = clientSnapshot.GetRawText() + "|" + filter + "|" + query;
        if (data == previousClients) return;
        bindingClients = true;
        try { Populate(clients, entries, "id", selectedClientId); }
        finally { bindingClients = false; }
        previousClients = data;
        RefreshClientActions();
    }

    private static bool Contains(string? text, string value) => text?.Contains(value, StringComparison.CurrentCultureIgnoreCase) == true;

    private static void Populate(DataGridView grid, IEnumerable<JsonElement> entries, string key, string? selected)
    {
        bool clientList = key == "id";
        var table = new System.Data.DataTable();
        string[] columns = clientList ? ["name", "active", "leaseSeconds", "expires", "lastIp", "lastRequest", "id", "enabled"] :
            ["clientName", "ip", "expires", "remaining", "phase", "ruleId"];
        foreach (var column in columns) table.Columns.Add(column, column == "enabled" ? typeof(bool) : typeof(string));
        foreach (var item in entries)
        {
            var row = table.NewRow();
            foreach (var column in columns)
            {
                if (column == "remaining") continue;
                if (column == "enabled") { row[column] = item.GetProperty(column).GetBoolean(); continue; }
                row[column] = column == "active"
                    ? item.GetProperty("active").GetBoolean() ? T("Активен", "Active")
                        : item.GetProperty("enabled").GetBoolean() ? T("Истёк", "Expired") : T("Отозван", "Revoked")
                    : FormatCell(new KeyValue(item.GetProperty(column), column));
            }
            table.Rows.Add(row);
        }
        grid.DataSource = table;
        foreach (DataGridViewColumn column in grid.Columns)
        {
            column.Visible = column.Name != key && column.Name != "enabled";
            column.HeaderText = column.Name switch
            {
                "clientName" => T("Клиент", "Client"),
                "name" => T("Имя", "Name"),
                "ip" => T("IP-адрес", "IP address"),
                "lastIp" => T("Последний IP", "Last IP"),
                "active" or "phase" => T("Статус", "Status"),
                "expires" => T("Действует до", "Valid until"),
                "remaining" => T("Осталось", "Remaining"),
                "lastRequest" => T("Последний запрос", "Last request"),
                "leaseSeconds" => T("Окно доступа", "Access window"),
                _ => column.Name
            };
            column.FillWeight = column.Name is "clientName" or "name" ? 125 :
                column.Name is "remaining" or "phase" ? 85 : 100;
            if (column.Name is "ip" or "lastIp" or "lastRequest" or "remaining") column.DefaultCellStyle.Font = Theme.Mono;
        }
        grid.ClearSelection();
        if (selected != null)
        {
            foreach (DataGridViewRow row in grid.Rows)
            {
                if (row.Cells[key].Value?.ToString() != selected) continue;
                grid.CurrentCell = row.Cells[0];
                row.Selected = true;
                break;
            }
        }
    }

    private void UpdateLeaseTimers()
    {
        if (!leases.Columns.Contains("remaining")) return;
        var now = sampledServerTime + System.Diagnostics.Stopwatch.GetElapsedTime(serverTimeSample);
        int count = 0;
        foreach (DataGridViewRow row in leases.Rows)
        {
            if (!leaseExpiries.TryGetValue(row.Cells["ruleId"].Value?.ToString() ?? "", out var expiry)) continue;
            var left = expiry - now;
            if (left > TimeSpan.Zero && row.Cells["phase"].Value?.ToString() == T("Активно", "Active")) count++;
            string text = left <= TimeSpan.Zero ? "00:00" :
                left.TotalDays >= 1 ? T($@"{(int)left.TotalDays} д {left:hh\:mm}", $@"{(int)left.TotalDays} d {left:hh\:mm}") :
                left.TotalHours >= 1 ? left.ToString(@"hh\:mm\:ss") : left.ToString(@"mm\:ss");
            if (!Equals(row.Cells["remaining"].Value, text)) row.Cells["remaining"].Value = text;
        }
        leaseCount.Text = T($"Временные разрешения ({count})", $"Temporary grants ({count})");
    }

    private readonly record struct KeyValue(JsonElement Value, string Name);
    private static string FormatCell(KeyValue property)
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
