using portGate.Core;
using static portGate.Manager.PanelLanguage;

namespace portGate.Manager;
internal enum ClientPlatform { Windows, MacOS }

internal sealed class PlanDialog : Form
{
    public PlanDialog(FirewallPlan plan, bool confirmApply)
    {
        Text = confirmApply ? T("Проверка перед применением защиты", "Review before applying protection") :
            T("Подробности плана брандмауэра", "Firewall plan details");
        Font = Theme.Body;
        BackColor = Theme.Canvas;
        ForeColor = Theme.Text;
        ShowInTaskbar = false;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(710, 440);
        MinimumSize = new Size(500, 320);
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = MaximizeBox = false;
        var tabs = new TabControl { Dock = DockStyle.Fill };
        var summary = new TabPage(T("Сводка", "Summary")) { BackColor = Theme.Surface };
        var text = new RichTextBox
        {
            Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, ReadOnly = true,
            BackColor = Theme.Surface, ForeColor = Theme.Text, DetectUrls = false
        };
        summary.Controls.Add(text);
        tabs.TabPages.Add(summary);
        text.AppendText(confirmApply
            ? T("Откройте новый RDP-сеанс с адреса из белого списка. На подтверждение даётся 120 секунд. По истечении времени прежние правила будут восстановлены.", "Open a new RDP session from an allowlisted address. You have 120 seconds to confirm. The previous rules will be restored if time expires.")
            : T($"Порт RDP: {plan.RdpPort}", $"RDP port: {plan.RdpPort}"));
        void Section(string title, int color, IEnumerable<string> details)
        {
            text.AppendText("\r\n\r\n");
            text.SelectionColor = Theme.Pick(color, SystemColors.WindowText);
            text.SelectionFont = Theme.CardTitle;
            text.AppendText(title);
            text.SelectionFont = Theme.Body;
            text.SelectionColor = Theme.Text;
            string items = string.Join("\r\n", details.Select(item => "• " + DisplayDetail(item)));
            text.AppendText("\r\n" + (items.Length == 0 ? T("Нет.", "None.") : items));
        }
        Section(T("Конфликты", "Conflicts"), 0xDC2626, plan.Conflicts);
        Section(T("Предупреждения", "Warnings"), 0xB45309, plan.Warnings);
        Section(T("Правила к отключению", "Rules to disable"), 0x2563EB, plan.Disable.Select(rule =>
            $"{rule.Name} · {rule.Identity} · {(rule.Protocol == 6 ? "TCP" : rule.Protocol == 17 ? "UDP" : rule.Protocol.ToString())} {rule.Ports}"));
        text.SelectionStart = 0;
        var technical = new TabPage(T("Технические данные (JSON)", "Technical data (JSON)"));
        technical.Controls.Add(JsonConfigDialog.Editor(Json.Write(plan), readOnly: true));
        tabs.TabPages.Add(technical);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
        var close = new ActionButton() { Text = confirmApply ? T("Отмена", "Cancel") : T("Закрыть", "Close"), DialogResult = DialogResult.Cancel };
        if (confirmApply) buttons.Controls.Add(new ActionButton(ActionStyle.Primary)
            { Text = T("Применить защиту", "Apply protection"), DialogResult = DialogResult.OK, Enabled = plan.Safe });
        buttons.Controls.Add(close);
        CancelButton = close;
        Controls.Add(tabs);
        Controls.Add(buttons);
        Shown += (_, _) => close.Focus();
    }
}

internal sealed class JsonConfigDialog : Form
{
    public static TextBox Editor(string json, bool readOnly) => new()
    {
        Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Both, WordWrap = false,
        ReadOnly = readOnly, Text = json, Font = Theme.Mono, BackColor = Theme.Surface, ForeColor = Theme.Text
    };

    public JsonConfigDialog(string json, bool readOnly, Func<Config, Task> saveConfig)
    {
        Text = T("Расширенные настройки (JSON)", "Advanced settings (JSON)");
        Font = Theme.Body;
        BackColor = Theme.Canvas;
        Size = new Size(760, 520);
        MinimumSize = new Size(480, 300);
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        var editor = Editor(json, readOnly);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
        var close = new ActionButton() { Text = T("Закрыть", "Close"), DialogResult = DialogResult.Cancel };
        if (!readOnly)
        {
            var save = new ActionButton(ActionStyle.Primary) { Text = T("Сохранить JSON", "Save JSON") };
            save.Click += async (_, _) =>
            {
                save.Enabled = close.Enabled = editor.Enabled = false;
                try
                {
                    var next = Json.Read<Config>(editor.Text);
                    next.Validate();
                    await saveConfig(next);
                    DialogResult = DialogResult.OK;
                }
                catch (Exception error)
                {
                    MessageBox.Show(this, DisplayDetail(error.Message), T("Настройки не сохранены", "Settings could not be saved"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                finally { save.Enabled = close.Enabled = editor.Enabled = true; }
            };
            FormClosing += (_, e) => { if (!save.Enabled && DialogResult != DialogResult.OK) e.Cancel = true; };
            buttons.Controls.Add(save);
        }
        buttons.Controls.Add(close);
        Controls.Add(editor);
        Controls.Add(buttons);
        CancelButton = close;
    }
}

internal sealed class ClientDialog : Form
{
    internal static string MacHelp => T("На Mac откройте .applescript в Редакторе скриптов, затем нажмите «Выполнить». Чтобы получить .scpt, сохраните файл на Mac в формате «Скрипт».", "On the Mac, open the .applescript in Script Editor and select Run. To get a .scpt file, save it on the Mac in Script format.");
    private readonly TextBox name = new() { Width = 340, Text = T("Пользователь", "User") };
    private readonly TextBox server = new() { Width = 340 };
    private readonly DurationInput duration = new(300);
    private readonly CheckBox limited = new() { AutoSize = true, Text = T("Ограничить срок действия ключа", "Set an expiry date for the key") };
    private readonly DateTimePicker expiry = new() { Value = DateTime.Now.AddMonths(1), Format = DateTimePickerFormat.Short };
    private readonly CheckBox launch = new() { AutoSize = true, Text = T("Запустить RDP после авторизации", "Start RDP after authorization") };
    private readonly RadioButton windows = PlatformOption("Windows (.bat / .ps1)");
    private readonly RadioButton macOS = PlatformOption("macOS (.applescript)");

    private static RadioButton PlatformOption(string caption) => new()
    {
        Appearance = Appearance.Button, AutoSize = true, Text = caption, Padding = new Padding(5),
        FlatStyle = SystemInformation.HighContrast ? FlatStyle.Standard : FlatStyle.Flat, Margin = new Padding(0)
    };
    public string ClientName => name.Text.Trim(); public string Server => server.Text.Trim(); public int Seconds => duration.Seconds;
    public string Expiry => limited.Checked ? new DateTimeOffset(expiry.Value.Date.AddDays(1)).ToUniversalTime().ToString("O") : "";
    public ClientPlatform Platform => macOS.Checked ? ClientPlatform.MacOS : ClientPlatform.Windows;
    public bool LaunchRdp => Platform == ClientPlatform.Windows && launch.Checked;
    public ClientDialog(bool export, Config config, ClientRecord? existing = null, bool exportOnly = false)
    {
        server.Text = config.ServerAddress; duration.Seconds = existing?.LeaseSeconds ?? config.LeaseSeconds;
        if (existing != null) { name.Text = existing.Name; limited.Checked = existing.Expires != null; if (existing.Expires != null) expiry.Value = existing.Expires.Value.LocalDateTime.Date.AddDays(-1); }
        Text = exportOnly ? T("Сохранить скрипт доступа", "Save access script") : export ? T("Создать клиента доступа", "Create access client") : T("Изменить клиента доступа", "Edit access client");
        ClientSize = new Size(470, export ? (exportOnly ? 330 : 550) : 280);
        Font = new Font("Segoe UI", 10);
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        BackColor = Theme.Canvas;
        ForeColor = Theme.Text;
        var content = new Panel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(12) };
        var sections = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, ColumnCount = 1 };
        sections.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        content.Controls.Add(sections);

        FlowLayoutPanel Section(string title)
        {
            var card = new CardPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(12), Margin = new Padding(0, 0, 0, 8) };
            var body = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false, FlowDirection = FlowDirection.TopDown };
            body.Controls.Add(new Label { Text = title, Font = Theme.CardTitle, AutoSize = true });
            card.Controls.Add(body);
            sections.Controls.Add(card);
            return body;
        }

        void Field(Control parent, string caption, Control control)
        {
            parent.Controls.Add(new Label { Text = caption, AutoSize = true });
            control.AccessibleName = caption;
            parent.Controls.Add(control);
        }

        if (!exportOnly)
        {
            var profile = Section(T("1. Профиль доступа", "1. Access profile"));
            Field(profile, T("Название клиента", "Client name"), name);
            Field(profile, T("Окно доступа", "Access window"), duration);
            profile.Controls.Add(limited);
            profile.Controls.Add(expiry);
            expiry.Enabled = limited.Checked;
            limited.CheckedChanged += (_, _) => expiry.Enabled = limited.Checked;
        }
        if (export)
        {
            var pass = Section(exportOnly ? T("Параметры пропуска", "Pass settings") : T("2. Параметры пропуска", "2. Pass settings"));
            Field(pass, T("IP или DNS сервера", "Server IP address or DNS name"), server);
            var options = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
            options.Controls.AddRange([windows, macOS]);
            windows.Checked = true;
            pass.Controls.Add(options);
            var platformHelp = new Label { AutoSize = true, MaximumSize = new Size(395, 0), ForeColor = Theme.Secondary };
            pass.Controls.Add(platformHelp);
            pass.Controls.Add(launch);
            void UpdatePlatform()
            {
                bool mac = Platform == ClientPlatform.MacOS;
                launch.Visible = !mac;
                platformHelp.Text = mac ? MacHelp : T("Выберите .bat для запуска двойным щелчком или .ps1 для Windows PowerShell.", "Choose .bat for double-click use or .ps1 for Windows PowerShell.");
                if (SystemInformation.HighContrast) return;
                windows.BackColor = mac ? Theme.Surface : Theme.AccentSoft;
                macOS.BackColor = mac ? Theme.AccentSoft : Theme.Surface;
            }
            macOS.CheckedChanged += (_, _) => UpdatePlatform();
            UpdatePlatform();
        }
        var ok = new ActionButton(ActionStyle.Primary) { Text = export ? T("Выбрать файл…", "Choose file…") : T("Сохранить", "Save") };
        var cancel = new ActionButton() { Text = T("Отмена", "Cancel"), DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => {
            try {
                if (!exportOnly && ClientName.Length is < 1 or > 100) throw new ArgumentException(T("Введите имя клиента длиной от 1 до 100 символов.", "Enter a client name of 1 to 100 characters."));
                if (export) AccessExport.ValidateServer(Server);
                if (!exportOnly && (Seconds < 30 || Seconds > config.MaxLeaseSeconds)) throw new ArgumentException(T("Окно должно быть от 30 секунд до ", "The access window must be between 30 seconds and ") + config.MaxLeaseSeconds / 3600m + T(" ч. Максимум изменяется в настройках.", " hours. You can change the maximum in Settings."));
                DialogResult = DialogResult.OK; Close();
            } catch (ArgumentException e) { MessageBox.Show(this, DisplayDetail(e.Message), T("Проверьте настройки клиента", "Check client settings"), MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        };
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Bottom, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(8) };
        buttons.Controls.AddRange([ok, cancel]);
        Controls.Add(content);
        Controls.Add(buttons);
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
