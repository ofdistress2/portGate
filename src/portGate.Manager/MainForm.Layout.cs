using static portGate.Manager.PanelLanguage;

namespace portGate.Manager;

internal sealed partial class MainForm
{
    private static string VersionLabel => typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "";
    private readonly Dictionary<Button, Func<bool>> actions = [];
    private readonly List<(TableLayoutPanel Page, NavButton Nav, string Title, string Subtitle, Control HeaderActions)> navigation = [];
    private readonly Panel pageHost = new() { Dock = DockStyle.Fill };
    private readonly Label pageTitle = new() { AutoSize = true, Font = Theme.Heading };
    private readonly Label pageSubtitle = new() { AutoSize = true, ForeColor = Theme.Secondary };
    private readonly StatusLabel serviceCardStatus = new("—");
    private readonly StatusLabel policyCardStatus = new("—");
    private readonly Label leaseCount = Copy(T("Временные разрешения", "Temporary grants"), heading: true);
    private readonly Label selectedClient = Copy("");
    private readonly Label settingsStatus = Copy("");
    private readonly Label portLock = new()
    {
        Text = T("Занято активной политикой", "Locked by active policy"), AutoSize = true, Visible = false,
        ForeColor = Theme.Pick(0xB45309, SystemColors.WindowText)
    };
    private readonly TextBox clientSearch = new() { Width = 240 };
    private readonly TextBox journalSearch = new() { Width = 240 };
    private readonly ComboBox clientFilter = new() { Width = 135, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ComboBox journalFilter = new() { Width = 135, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly ProgressBar confirmationProgress = new()
    {
        Maximum = 120, Width = 130, Height = 9, TabStop = false, Margin = new Padding(12, 7, 0, 0),
        AccessibleName = T("Оставшееся время подтверждения", "Remaining confirmation time")
    };
    private CardPanel confirmationBanner = null!;
    private CardPanel setupBanner = null!;
    private TableLayoutPanel header = null!;
    private int selectedPage = -1;
    private bool allowlistEditable = true;

    private TableLayoutPanel[] BuildShell()
    {
        var shell = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 240));
        shell.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        shell.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        Controls.Add(shell);
        var sidebar = new Panel { Dock = DockStyle.Fill, Margin = new Padding(0), BackColor = Theme.Surface, Padding = new Padding(12) };
        shell.Controls.Add(sidebar, 0, 0);
        var brandText = Stack();
        brandText.Controls.Add(new Label { Text = "portGate", AutoSize = true, Font = Theme.Heading });
        brandText.Controls.Add(Copy(VersionLabel + " · Windows Server"));
        var brand = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(5, 7, 0, 14), WrapContents = false };
        brand.Controls.AddRange([new ShieldMark(), brandText]);

        var footer = new CardPanel { Padding = new Padding(9), BackColor = Theme.Subtle, Dock = DockStyle.Bottom };
        var status = AddStack(footer);
        serviceStatus.Font = protectionStatus.Font = Theme.CardTitle;
        connectionStatus.Font = Theme.Mono;
        status.Controls.AddRange([serviceStatus, protectionStatus, connectionStatus]);
        sidebar.Controls.Add(footer);

        var work = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(18, 12, 18, 5), Margin = new Padding(0) };
        work.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        work.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        work.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        shell.Controls.Add(work, 1, 0);
        header = new TableLayoutPanel { AutoSize = true, Dock = DockStyle.Top, ColumnCount = 2, RowCount = 1, Margin = new Padding(0, 0, 0, 10) };
        header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var titles = Stack();
        titles.Controls.AddRange([pageTitle, pageSubtitle]);
        header.Controls.Add(titles, 0, 0);
        work.Controls.Add(header, 0, 0);
        work.Controls.Add(pageHost, 0, 1);
        var bottom = new StatusStrip { SizingGrip = false, BackColor = Theme.Canvas, ForeColor = Theme.Secondary, Dock = DockStyle.Fill, Margin = new Padding(0) };
        bottom.Items.Add(message);
        work.Controls.Add(bottom, 0, 2);

        var definitions = new (string Title, string Subtitle, string? Caption, Func<Task>? Run)[]
        {
            (T("Обзор", "Overview"), T("Служба, защита RDP и временные разрешения", "Service, RDP protection and temporary grants"), T("↻ Обновить", "↻ Refresh"), RefreshData),
            (T("Клиенты", "Clients"), T("Пропуска и скрипты доступа", "Access passes and scripts"), T("+ Создать и сохранить скрипт…", "+ Create and save script…"), CreateClient),
            (T("Настройки", "Settings"), T("Сеть, белый список и окна доступа", "Network, allowlist and access windows"), null, null),
            (T("Журнал", "Journal"), T("Недавние события службы", "Recent service events"), null, null)
        };
        for (int i = 0; i < definitions.Length; i++)
        {
            var (title, subtitle, caption, run) = definitions[i];
            int index = i;
            var nav = new NavButton(title);
            nav.Click += async (_, _) => await SelectPage(index);
            var page = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 0, Visible = false, Margin = new Padding(0) };
            page.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pageHost.Controls.Add(page);
            var context = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Anchor = AnchorStyles.Top | AnchorStyles.Right, Margin = new Padding(4, 1, 0, 0) };
            if (caption != null && run != null)
                Button(context, caption, run, i == 1 ? ActionStyle.Primary : ActionStyle.Secondary);
            if (i == 3)
            {
                var refresh = Button(context, "↻", RefreshJournal);
                var clear = Button(context, "🗑", ClearJournal, ActionStyle.DangerOutline);
                refresh.AccessibleName = T("Обновить журнал", "Refresh journal");
                clear.AccessibleName = T("Очистить журнал", "Clear journal");
                actionHints.SetToolTip(refresh, refresh.AccessibleName);
                actionHints.SetToolTip(clear, clear.AccessibleName);
            }
            navigation.Add((page, nav, title, subtitle, context));
        }
        foreach (var entry in navigation.AsEnumerable().Reverse()) sidebar.Controls.Add(entry.Nav);
        sidebar.Controls.Add(brand);
        return navigation.Select(entry => entry.Page).ToArray();
    }

    private async Task SelectPage(int index, bool refresh = true)
    {
        if (selectedPage == index) return;
        if (selectedPage >= 0)
        {
            var old = navigation[selectedPage];
            old.Page.Visible = false;
            old.Nav.SetActive(false);
            header.Controls.Remove(old.HeaderActions);
        }
        selectedPage = index;
        var next = navigation[index];
        next.Page.Visible = true;
        next.Page.BringToFront();
        next.Nav.SetActive(true);
        pageTitle.Text = next.Title;
        pageSubtitle.Text = next.Subtitle;
        header.Controls.Add(next.HeaderActions, 1, 0);
        if (refresh && !busy)
        {
            if (index == 2) await Guard(RefreshData);
            if (index == 3) await Guard(RefreshJournal);
        }
    }

    private static Label Copy(string text, bool heading = false) => new()
    {
        Text = text, AutoSize = true, Font = heading ? Theme.CardTitle : Theme.Body,
        ForeColor = heading ? Theme.Text : Theme.Secondary, Margin = new Padding(0, 1, 0, 2)
    };

    private static void Heading(Control parent, string title) => parent.Controls.Add(Copy(title, heading: true));

    private static FlowLayoutPanel Stack() => new()
    {
        AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = false,
        FlowDirection = FlowDirection.TopDown, Margin = new Padding(0)
    };

    private static FlowLayoutPanel AddStack(CardPanel card)
    {
        var body = Stack();
        body.Dock = DockStyle.Top;
        card.AutoSize = card.Dock != DockStyle.Fill;
        card.Controls.Add(body);
        void Fit()
        {
            int width = Math.Max(1, card.ClientSize.Width - card.Padding.Horizontal);
            foreach (Control child in body.Controls)
            {
                if (child is Label or FlowLayoutPanel) child.MaximumSize = new Size(width, 0);
                if (child is TextBox) child.Width = width;
            }
        }
        card.SizeChanged += (_, _) => Fit();
        body.ControlAdded += (_, _) => Fit();
        Fit();
        return body;
    }

    private static void Field(Control parent, string caption, Control input)
    {
        parent.Controls.Add(Copy(caption));
        input.AccessibleName = caption;
        parent.Controls.Add(input);
    }

    private static FlowLayoutPanel Row(Control parent)
    {
        var row = new FlowLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, WrapContents = true, Margin = new Padding(0, 3, 0, 0) };
        parent.Controls.Add(row);
        return row;
    }

    private static TableLayoutPanel TwoColumns()
    {
        var table = new TableLayoutPanel
        {
            ColumnCount = 2, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Top, Margin = new Padding(0)
        };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        return table;
    }

    private static FlowLayoutPanel SettingsCard(TableLayoutPanel grid, int column, int row, string title, int span = 1)
    {
        var card = new CardPanel
        {
            Dock = DockStyle.Top,
            Padding = new Padding(11),
            Margin = span == 2 ? new Padding(0, 0, 0, 10) :
                new Padding(column == 1 ? 7 : 0, 0, column == 0 ? 7 : 0, 10)
        };
        while (grid.RowCount <= row) { grid.RowCount++; grid.RowStyles.Add(new RowStyle(SizeType.AutoSize)); }
        grid.Controls.Add(card, column, row);
        grid.SetColumnSpan(card, span);
        var body = AddStack(card);
        Heading(body, title);
        return body;
    }

    private static void AddRow(TableLayoutPanel table, Control control, bool fill = false)
    {
        int row = table.RowCount++;
        table.RowStyles.Add(fill ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
        control.Margin = new Padding(0, 0, 0, fill ? 0 : 8);
        control.Dock = fill ? DockStyle.Fill : DockStyle.Top;
        table.Controls.Add(control, 0, row);
    }

    private static CardPanel GridCard(DataGridView grid)
    {
        var card = new CardPanel { Padding = new Padding(9), Dock = DockStyle.Fill };
        card.Controls.Add(grid);
        return card;
    }

    private static CardPanel FilterBar(TextBox search, ComboBox filter, string prompt, string[] options)
    {
        var card = new CardPanel { Padding = new Padding(10, 5, 10, 5) };
        var row = Row(AddStack(card));
        search.PlaceholderText = prompt;
        search.AccessibleName = prompt;
        filter.AccessibleName = T("Фильтр", "Filter");
        filter.Items.AddRange(options);
        filter.SelectedIndex = 0;
        row.Controls.AddRange([search, filter]);
        return card;
    }

    private void SetSettingsDirty(bool dirty)
    {
        settingsDirty = dirty;
        settingsStatus.Text = dirty ? T("Есть несохранённые изменения", "Unsaved changes") :
            T("Все изменения сохранены", "All changes saved");
        RefreshOverviewActions();
    }
}
